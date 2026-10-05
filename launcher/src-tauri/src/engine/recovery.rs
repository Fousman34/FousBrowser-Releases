//! Восстановление после аварийного завершения.
//!
//! # Что может остаться после краха
//!
//! Пока профиль работает, его данные лежат расшифрованными в `vault/tmp/<uuid>/`.
//! Если лаунчер в этот момент упал (или его закрыли силой), на диске остаются:
//!
//! - расшифрованный каталог профиля;
//! - запись в `vault/index.json` в состоянии `running` или `sealing`;
//! - возможно, живой процесс движка, который продолжает писать в этот каталог.
//!
//! # Что делает восстановление
//!
//! 1. Для каждой осиротевшей записи проверяет, жив ли процесс. Завершает его
//!    **только** если путь к исполняемому файлу совпадает с записанным в
//!    журнале: по одному лишь номеру процесса убивать чужой процесс нельзя —
//!    номера переиспользуются.
//! 2. Затем по настройке (`orphan_policy`) либо шифрует данные обратно
//!    в контейнер, либо удаляет расшифрованную копию.
//! 3. Отдельно разбирает каталоги в `vault/tmp/`, которых нет в журнале:
//!    журнал мог быть потерян, а данные — остаться.
//! 4. Чистит журнал и возвращает отчёт для интерфейса.
//!
//! # Чего восстановление не делает
//!
//! Не удаляет **зашифрованные** контейнеры и не трогает ничего за пределами
//! `vault/tmp/`: путь из журнала проверяется на принадлежность этому каталогу,
//! чтобы повреждённый журнал не привёл к удалению чужих файлов.

use std::path::{Path, PathBuf};

use serde::Serialize;

use super::journal::{Journal, STATE_RUNNING, STATE_SEALING};
use super::process;
use crate::engine::force_kill;
use crate::vault::metadata::OrphanPolicy;
use crate::vault::profiles::wipe_dir;
use crate::vault::{PlaintextState, Result, UnlockedVault, VaultError};

/// Что сделано при восстановлении.
#[derive(Debug, Default, Clone, Serialize, PartialEq, Eq)]
pub struct RecoveryReport {
    /// Профили, данные которых зашифрованы обратно.
    pub sealed: Vec<String>,
    /// Профили, расшифрованные копии которых удалены.
    pub deleted: Vec<String>,
    /// Завершённые процессы движков.
    pub stopped_pids: Vec<u32>,
    /// Неудачи: профиль и причина.
    pub failed: Vec<Failure>,
}

/// Профиль, который не удалось разобрать.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct Failure {
    pub profile_id: String,
    pub message: String,
}

impl RecoveryReport {
    /// Работало ли восстановление хоть что-то.
    pub fn is_empty(&self) -> bool {
        self.sealed.is_empty()
            && self.deleted.is_empty()
            && self.stopped_pids.is_empty()
            && self.failed.is_empty()
    }

    /// Строки для интерфейса: то, что человек должен увидеть.
    pub fn notes(&self) -> Vec<String> {
        let mut notes = Vec::new();
        if !self.stopped_pids.is_empty() {
            notes.push(format!(
                "завершены процессы движков, оставшиеся после сбоя: {}",
                self.stopped_pids.len()
            ));
        }
        if !self.sealed.is_empty() {
            notes.push(format!(
                "данные профилей зашифрованы обратно после сбоя: {}",
                self.sealed.len()
            ));
        }
        if !self.deleted.is_empty() {
            notes.push(format!(
                "расшифрованные копии удалены по настройке: {}",
                self.deleted.len()
            ));
        }
        for failure in &self.failed {
            notes.push(format!(
                "профиль {}: {failure_message}",
                &failure.profile_id[..8.min(failure.profile_id.len())],
                failure_message = failure.message
            ));
        }
        notes
    }

    fn fail(&mut self, profile_id: &str, message: impl Into<String>) {
        self.failed.push(Failure {
            profile_id: profile_id.to_string(),
            message: message.into(),
        });
    }
}

/// Разбирает последствия аварийного завершения.
pub fn recover(vault: &mut UnlockedVault) -> Result<RecoveryReport> {
    let vault_dir = vault.dir().to_path_buf();
    let temp_root = vault_dir.join("tmp");
    let policy = vault.metadata().settings.orphan_policy;

    let mut journal = Journal::load(&vault_dir);
    let mut report = RecoveryReport::default();
    let mut handled: Vec<String> = Vec::new();

    for entry in journal.orphans() {
        let profile_id = entry.profile_id.clone();
        handled.push(profile_id.clone());

        // 1. Живой процесс движка должен быть завершён до шифрования:
        //    иначе браузер продолжит писать в каталог, который мы забираем.
        if entry.state == STATE_RUNNING || entry.state == STATE_SEALING {
            if let Some(stopped) = stop_orphan_process(&entry) {
                report.stopped_pids.push(stopped);
            }
        }

        // 2. Путь из журнала обязан указывать внутрь vault/tmp.
        let Some(directory) = safe_temp_dir(&temp_root, &entry.temp_dir) else {
            report.fail(
                &profile_id,
                "путь из журнала не принадлежит каталогу расшифрованных копий",
            );
            journal.remove(&profile_id);
            continue;
        };

        if !directory.is_dir() {
            // Данных нет — запись просто устарела.
            journal.remove(&profile_id);
            continue;
        }

        if let Err(error) = resolve_plaintext(vault, &profile_id, &directory, policy, &mut report) {
            report.fail(&profile_id, error.to_string());
            continue;
        }
        journal.remove(&profile_id);
    }

    // 3. Каталоги, которых нет в журнале: журнал мог быть потерян.
    if let Ok(entries) = std::fs::read_dir(&temp_root) {
        for entry in entries.flatten() {
            if !entry.file_type().map(|kind| kind.is_dir()).unwrap_or(false) {
                continue;
            }
            let profile_id = entry.file_name().to_string_lossy().to_string();
            if handled.contains(&profile_id) {
                continue;
            }
            // Профиль мог быть удалён вместе с данными: тогда каталог лишний.
            let known = vault.metadata().find(&profile_id).is_some();
            if !known {
                if let Err(error) = wipe_dir(&entry.path()) {
                    report.fail(&profile_id, format!("не удалось удалить копию: {error}"));
                } else {
                    report.deleted.push(profile_id);
                }
                continue;
            }
            if let Err(error) =
                resolve_plaintext(vault, &profile_id, &entry.path(), policy, &mut report)
            {
                report.fail(&profile_id, error.to_string());
            }
        }
    }

    journal.save(&vault_dir)?;
    Ok(report)
}

/// Применяет политику к одному расшифрованному каталогу.
fn resolve_plaintext(
    vault: &UnlockedVault,
    profile_id: &str,
    directory: &Path,
    policy: OrphanPolicy,
    report: &mut RecoveryReport,
) -> Result<()> {
    match policy {
        OrphanPolicy::EncryptBack => {
            // Пустая копия: шифровать нечего, каталог просто убирается.
            if vault.plaintext_state(profile_id)? == PlaintextState::Absent {
                let _ = wipe_dir(directory);
                return Ok(());
            }
            vault.seal_profile(profile_id, directory)?;
            vault.discard_plaintext(profile_id)?;
            report.sealed.push(profile_id.to_string());
        }
        OrphanPolicy::Delete => {
            wipe_dir(directory)?;
            report.deleted.push(profile_id.to_string());
        }
    }
    Ok(())
}

/// Завершает процесс движка, оставшийся после сбоя.
///
/// Возвращает идентификатор, если процесс был завершён. Ничего не делает,
/// если процесса нет или он не совпадает с записанным в журнале
/// исполняемым файлом: номера процессов переиспользуются, и убивать по ним
/// чужой процесс нельзя.
fn stop_orphan_process(entry: &super::journal::Entry) -> Option<u32> {
    if entry.pid == 0 {
        return None;
    }
    let live = process::executable_of(entry.pid)?;

    let matches = if entry.engine_program.is_empty() {
        // Старые записи без пути к движку: завершать не рискуем.
        return None;
    } else {
        let recorded = PathBuf::from(&entry.engine_program);
        paths_equal(&live, &recorded)
    };
    if !matches {
        return None;
    }

    let _ = force_kill(entry.pid);
    Some(entry.pid)
}

/// Сравнивает пути без учёта регистра: в Windows это одно и то же имя.
fn paths_equal(left: &Path, right: &Path) -> bool {
    left.to_string_lossy()
        .eq_ignore_ascii_case(&right.to_string_lossy())
}

/// Проверяет, что путь из журнала указывает внутрь каталога расшифрованных копий.
fn safe_temp_dir(temp_root: &Path, recorded: &str) -> Option<PathBuf> {
    let path = PathBuf::from(recorded);
    let root = temp_root
        .canonicalize()
        .unwrap_or_else(|_| temp_root.to_path_buf());
    let candidate = path.canonicalize().unwrap_or(path.clone());
    if candidate.starts_with(&root) && candidate != root {
        Some(path)
    } else {
        None
    }
}

/// Ошибка восстановления с понятным текстом (для отчёта).
pub fn describe(error: &VaultError) -> String {
    error.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::journal::Entry;
    use crate::vault::kdf::KdfParams;
    use crate::vault::metadata::ProfileKind;
    use crate::vault::session::Vault;
    use std::fs;

    const PASSWORD: &str = "correct-horse-battery";

    fn vault(dir: &Path) -> UnlockedVault {
        Vault::create_with_params(
            dir,
            PASSWORD,
            KdfParams {
                algorithm: "argon2id".to_string(),
                m_cost_kib: 64,
                t_cost: 1,
                p_cost: 1,
            },
        )
        .unwrap()
    }

    fn entry(vault: &UnlockedVault, profile_id: &str, state: &str) -> Entry {
        Entry {
            profile_id: profile_id.to_string(),
            pid: 0,
            temp_dir: vault
                .temp_profile_dir(profile_id)
                .to_string_lossy()
                .to_string(),
            state: state.to_string(),
            engine_version: "test".to_string(),
            started_unix: crate::vault::unix_now(),
            engine_program: String::new(),
        }
    }

    #[test]
    fn crash_after_unseal_encrypts_data_back() {
        let tmp = tempfile::tempdir().unwrap();
        let mut vault = vault(tmp.path());
        let id = vault
            .create_profile("Профиль", ProfileKind::Normal, None, None)
            .unwrap()
            .id;

        // Изображаем сбой: данные расшифрованы, журнал говорит «работает».
        let plain = vault.temp_profile_dir(&id);
        vault.unseal_profile(&id, &plain).unwrap();
        fs::write(plain.join("Cookies"), b"secret-cookie").unwrap();

        let mut journal = Journal::default();
        journal.upsert(entry(&vault, &id, STATE_RUNNING));
        journal.save(vault.dir()).unwrap();

        let report = recover(&mut vault).unwrap();

        assert_eq!(report.sealed, vec![id.clone()]);
        assert!(report.failed.is_empty(), "{:?}", report.failed);
        assert!(!plain.exists(), "расшифрованная копия удалена");
        assert!(
            Journal::load(vault.dir()).entries.is_empty(),
            "журнал очищен"
        );

        // Данные действительно вернулись в контейнер.
        let back = vault.temp_profile_dir(&id);
        vault.unseal_profile(&id, &back).unwrap();
        assert_eq!(fs::read(back.join("Cookies")).unwrap(), b"secret-cookie");
    }

    #[test]
    fn delete_policy_removes_the_plaintext_copy() {
        let tmp = tempfile::tempdir().unwrap();
        let mut vault = vault(tmp.path());
        let id = vault
            .create_profile("Профиль", ProfileKind::Normal, None, None)
            .unwrap()
            .id;
        vault.metadata_mut().settings.orphan_policy = OrphanPolicy::Delete;

        let plain = vault.temp_profile_dir(&id);
        vault.unseal_profile(&id, &plain).unwrap();
        fs::write(plain.join("Cookies"), b"secret-cookie").unwrap();

        let mut journal = Journal::default();
        journal.upsert(entry(&vault, &id, STATE_SEALING));
        journal.save(vault.dir()).unwrap();

        let report = recover(&mut vault).unwrap();
        assert_eq!(report.deleted, vec![id.clone()]);
        assert!(report.sealed.is_empty());
        assert!(!plain.exists());
    }

    #[test]
    fn plaintext_directory_without_journal_entry_is_handled() {
        let tmp = tempfile::tempdir().unwrap();
        let mut vault = vault(tmp.path());
        let id = vault
            .create_profile("Профиль", ProfileKind::Normal, None, None)
            .unwrap()
            .id;
        let plain = vault.temp_profile_dir(&id);
        vault.unseal_profile(&id, &plain).unwrap();
        fs::write(plain.join("History"), b"visit").unwrap();

        // Журнала нет вовсе: данные всё равно должны быть зашифрованы обратно.
        let report = recover(&mut vault).unwrap();
        assert_eq!(report.sealed, vec![id.clone()]);
        assert!(!plain.exists());
    }

    #[test]
    fn directory_of_a_deleted_profile_is_removed() {
        let tmp = tempfile::tempdir().unwrap();
        let mut vault = vault(tmp.path());
        // Профиль создаётся и тут же исчезает из метаданных: остаётся только
        // расшифрованный каталог, как после удаления профиля вместе с данными.
        let id = vault
            .create_profile("Профиль", ProfileKind::Normal, None, None)
            .unwrap()
            .id;
        vault.delete_profile(&id).unwrap();

        let stranger = vault
            .dir()
            .join("tmp")
            .join("11111111-2222-3333-4444-555555555555");
        fs::create_dir_all(&stranger).unwrap();
        fs::write(stranger.join("Cookies"), b"datr").unwrap();

        let report = recover(&mut vault).unwrap();
        assert!(report.sealed.is_empty());
        assert_eq!(report.deleted.len(), 1, "неизвестный каталог удаляется");
        assert!(!stranger.exists());
    }

    #[test]
    fn journal_path_outside_the_temp_root_is_refused() {
        let tmp = tempfile::tempdir().unwrap();
        let mut vault = vault(tmp.path());
        let id = vault
            .create_profile("Профиль", ProfileKind::Normal, None, None)
            .unwrap()
            .id;

        // Подменённый журнал указывает на чужой каталог с данными.
        let outside = tmp.path().join("важное");
        fs::create_dir_all(&outside).unwrap();
        fs::write(outside.join("файл.txt"), "не трогать".as_bytes()).unwrap();

        let mut journal = Journal::default();
        let mut forged = entry(&vault, &id, STATE_RUNNING);
        forged.temp_dir = outside.to_string_lossy().to_string();
        journal.upsert(forged);
        journal.save(vault.dir()).unwrap();

        let report = recover(&mut vault).unwrap();
        assert_eq!(report.failed.len(), 1);
        assert!(report.failed[0].message.contains("не принадлежит"));
        assert!(outside.join("файл.txt").exists(), "чужой каталог не тронут");
    }

    #[test]
    fn foreign_process_is_never_killed() {
        let tmp = tempfile::tempdir().unwrap();
        let mut vault = vault(tmp.path());
        let id = vault
            .create_profile("Профиль", ProfileKind::Normal, None, None)
            .unwrap()
            .id;

        let plain = vault.temp_profile_dir(&id);
        vault.unseal_profile(&id, &plain).unwrap();

        // Запись ссылается на живой процесс, но путь к движку не совпадает:
        // это чужой процесс, и завершать его нельзя.
        let mut journal = Journal::default();
        let mut forged = entry(&vault, &id, STATE_RUNNING);
        forged.pid = std::process::id();
        forged.engine_program = "D:/не-наш-браузер/browser.exe".to_string();
        journal.upsert(forged);
        journal.save(vault.dir()).unwrap();

        // Данные непустые: иначе каталог просто убирается, и проверять
        // «зашифровано обратно» было бы не на чем.
        fs::write(plain.join("Cookies"), b"data").unwrap();

        let report = recover(&mut vault).unwrap();
        assert!(
            report.stopped_pids.is_empty(),
            "чужой процесс не завершается"
        );
        // Данные при этом всё равно возвращаются в контейнер.
        assert_eq!(report.sealed, vec![id.clone()]);
    }

    #[test]
    fn our_own_process_is_recognised_and_stopped() {
        // Процесс с совпадающим путём опознаётся как наш движок. Проверяем
        // решение, не запуская настоящий браузер: подставляем свой процесс
        // и путь к его исполняемому файлу.
        let live = process::executable_of(std::process::id()).unwrap();
        let entry = Entry {
            profile_id: "p".to_string(),
            pid: std::process::id(),
            temp_dir: String::new(),
            state: STATE_RUNNING.to_string(),
            engine_version: "test".to_string(),
            started_unix: 0,
            engine_program: live.to_string_lossy().to_string(),
        };
        // Функция завершила бы процесс, поэтому проверяем только распознавание.
        assert!(paths_equal(&live, &PathBuf::from(&entry.engine_program)));
    }

    #[test]
    fn report_notes_are_human_readable() {
        let mut report = RecoveryReport::default();
        report
            .sealed
            .push("11111111-2222-3333-4444-555555555555".to_string());
        report.stopped_pids.push(42);
        report.fail("11111111-2222-3333-4444-555555555555", "нет доступа");

        let notes = report.notes();
        assert!(notes
            .iter()
            .any(|note| note.contains("зашифрованы обратно")));
        assert!(notes.iter().any(|note| note.contains("процессы движков")));
        assert!(notes.iter().any(|note| note.contains("нет доступа")));
        assert!(!RecoveryReport::default()
            .notes()
            .iter()
            .any(|note| !note.is_empty()));
    }
}
