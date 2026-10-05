//! Журнал запущенных движков: `vault/index.json`.
//!
//! Файл **не зашифрован** и содержит только то, что нужно для разбора
//! последствий аварийного завершения: идентификатор профиля, идентификатор
//! процесса, путь к расшифрованной копии, состояние и версию движка.
//! Ни имён профилей, ни настроек, ни прокси, ни ключей здесь нет.
//!
//! Почему открытый: до ввода мастер-пароля ключа ещё нет, а понять, какие
//! каталоги остались расшифрованными, нужно именно в этот момент.

use std::fs;
use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::paths;
use crate::vault::{Result, VaultError};

/// Имя файла журнала внутри каталога хранилища.
pub const INDEX_FILE: &str = "index.json";

/// Состояние: движок работает.
pub const STATE_RUNNING: &str = "running";

/// Состояние: движок остановлен, данные шифруются обратно.
pub const STATE_SEALING: &str = "sealing";

/// Версия формата журнала.
pub const JOURNAL_VERSION: u32 = 1;

/// Одна запись журнала.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Entry {
    pub profile_id: String,
    pub pid: u32,
    pub temp_dir: String,
    pub state: String,
    pub engine_version: String,
    pub started_unix: u64,
    /// Путь к исполняемому файлу движка.
    ///
    /// Нужен восстановлению после краха: завершать процесс можно только
    /// убедившись, что это тот самый движок. Номера процессов
    /// переиспользуются, поэтому одного `pid` недостаточно.
    ///
    /// Поле появилось позже первой версии формата, поэтому у старых записей
    /// его может не быть — тогда восстановление процесс не трогает.
    #[serde(default)]
    pub engine_program: String,
}

/// Журнал целиком.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Journal {
    pub version: u32,
    pub entries: Vec<Entry>,
}

impl Default for Journal {
    fn default() -> Self {
        Self {
            version: JOURNAL_VERSION,
            entries: Vec::new(),
        }
    }
}

impl Journal {
    /// Читает журнал. Отсутствующий или повреждённый файл даёт пустой журнал:
    /// данные профилей лежат в контейнерах, а не здесь, поэтому терять нечего,
    /// а падать из-за служебного файла нельзя.
    pub fn load(vault_dir: &Path) -> Self {
        let path = vault_dir.join(INDEX_FILE);
        match fs::read(&path) {
            Ok(bytes) => serde_json::from_slice(&bytes).unwrap_or_default(),
            Err(_) => Self::default(),
        }
    }

    /// Записывает журнал атомарно.
    pub fn save(&self, vault_dir: &Path) -> Result<()> {
        let bytes = serde_json::to_vec_pretty(self)?;
        paths::write_atomic(&vault_dir.join(INDEX_FILE), &bytes)?;
        Ok(())
    }

    /// Добавляет запись или заменяет прежнюю с тем же профилем.
    pub fn upsert(&mut self, entry: Entry) {
        match self
            .entries
            .iter_mut()
            .find(|item| item.profile_id == entry.profile_id)
        {
            Some(slot) => *slot = entry,
            None => self.entries.push(entry),
        }
    }

    /// Убирает запись профиля.
    pub fn remove(&mut self, profile_id: &str) {
        self.entries.retain(|item| item.profile_id != profile_id);
    }

    /// Запись профиля, если она есть.
    pub fn find(&self, profile_id: &str) -> Option<&Entry> {
        self.entries
            .iter()
            .find(|item| item.profile_id == profile_id)
    }

    /// Записи, которые после перезапуска считаются осиротевшими.
    pub fn orphans(&self) -> Vec<Entry> {
        self.entries
            .iter()
            .filter(|item| item.state == STATE_RUNNING || item.state == STATE_SEALING)
            .cloned()
            .collect()
    }

    /// Проверяет, что путь из записи указывает на каталог расшифрованных
    /// данных, а не куда-то ещё.
    pub fn orphan_is_plaintext(&self, entry: &Entry) -> bool {
        Path::new(&entry.temp_dir).is_dir()
    }
}

/// Ошибка чтения записи журнала (для диагностики).
pub fn describe_error(error: &VaultError) -> String {
    error.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(id: &str, state: &str) -> Entry {
        Entry {
            profile_id: id.to_string(),
            pid: 4242,
            temp_dir: format!("/tmp/{id}"),
            state: state.to_string(),
            engine_version: "1.0.0".to_string(),
            started_unix: 1_700_000_000,
            engine_program: "C:/browsers/FousBrowser.exe".to_string(),
        }
    }

    #[test]
    fn missing_journal_is_empty() {
        let tmp = tempfile::tempdir().unwrap();
        let journal = Journal::load(tmp.path());
        assert!(journal.entries.is_empty());
        assert_eq!(journal.version, JOURNAL_VERSION);
    }

    #[test]
    fn corrupt_journal_is_tolerated() {
        let tmp = tempfile::tempdir().unwrap();
        fs::write(tmp.path().join(INDEX_FILE), b"{ this is not json").unwrap();
        assert!(Journal::load(tmp.path()).entries.is_empty());
    }

    #[test]
    fn upsert_replaces_by_profile() {
        let mut journal = Journal::default();
        journal.upsert(entry("a", STATE_RUNNING));
        journal.upsert(entry("b", STATE_RUNNING));
        let mut updated = entry("a", STATE_SEALING);
        updated.pid = 7;
        journal.upsert(updated);

        assert_eq!(journal.entries.len(), 2);
        assert_eq!(journal.find("a").unwrap().pid, 7);
        assert_eq!(journal.find("a").unwrap().state, STATE_SEALING);
    }

    #[test]
    fn save_and_load_round_trip() {
        let tmp = tempfile::tempdir().unwrap();
        let mut journal = Journal::default();
        journal.upsert(entry("a", STATE_RUNNING));
        journal.upsert(entry("b", "stopped"));
        journal.save(tmp.path()).unwrap();

        let loaded = Journal::load(tmp.path());
        assert_eq!(loaded, journal);
    }

    #[test]
    fn remove_drops_only_the_named_profile() {
        let mut journal = Journal::default();
        journal.upsert(entry("a", STATE_RUNNING));
        journal.upsert(entry("b", STATE_RUNNING));
        journal.remove("a");
        assert!(journal.find("a").is_none());
        assert!(journal.find("b").is_some());
    }

    #[test]
    fn orphans_are_running_and_sealing_entries() {
        let mut journal = Journal::default();
        journal.upsert(entry("a", STATE_RUNNING));
        journal.upsert(entry("b", STATE_SEALING));
        journal.upsert(entry("c", "stopped"));

        let orphans = journal.orphans();
        assert_eq!(orphans.len(), 2);
        assert!(orphans.iter().any(|item| item.profile_id == "a"));
        assert!(orphans.iter().any(|item| item.profile_id == "b"));
    }

    #[test]
    fn journal_contains_no_secrets() {
        let mut journal = Journal::default();
        journal.upsert(Entry {
            profile_id: "11111111-2222-3333-4444-555555555555".to_string(),
            pid: 1,
            temp_dir: "/tmp/x".to_string(),
            state: STATE_RUNNING.to_string(),
            engine_version: "1.2.3".to_string(),
            started_unix: 1,
            engine_program: "C:/browsers/FousBrowser.exe".to_string(),
        });
        let text = serde_json::to_string(&journal).unwrap();
        for forbidden in ["password", "proxy", "seed", "master", "token"] {
            assert!(
                !text.to_lowercase().contains(forbidden),
                "в журнале не должно быть поля {forbidden}"
            );
        }
    }
}
