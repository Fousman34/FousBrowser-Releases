//! Операции над профилями: создание, клонирование, правка, удаление.
//!
//! Профиль — это запись в зашифрованных метаданных плюс каталог
//! `vault/profiles/<uuid>/` для его данных. Тип (Normal или Antidetect)
//! влияет только на то, какой движок будет запущен, но не на хранение.
//!
//! # Почему клон получает новое зерно
//!
//! Зерно отпечатка (`seed`) определяет, как движок подменяет параметры
//! окружения. Копия с тем же зерном выглядела бы для сайтов как тот же
//! самый браузер, поэтому клонирование всегда генерирует новое зерно.
//!
//! # Почему клон пока не переносит данные
//!
//! Данные профиля шифруются с AAD, в который входит UUID профиля. Скопировать
//! зашифрованные файлы под новым идентификатором нельзя — они перестанут
//! расшифровываться. Перенос cookies и логинов появится вместе с потоковым
//! шифрованием (этап CryptoFS): тогда клон соберётся из расшифрованной копии
//! и будет зашифрован заново своим ключом. Сейчас копируются настройки.

use std::fs;
use std::path::{Path, PathBuf};

use super::crypto;
use super::error::{Result, VaultError};
use super::metadata::{ProfileKind, ProfileMeta, ProxyConfig, MAX_PROFILE_NAME_LEN};
use super::session::{UnlockedVault, TEMP_DIR};

/// Проверяет и нормализует имя профиля.
///
/// Пробелы по краям отбрасываются: имя « Рабочий » и «Рабочий» для
/// пользователя одно и то же, а разные байты в списке — источник путаницы.
pub fn validate_name(name: &str) -> Result<String> {
    let trimmed = name.trim();
    let length = trimmed.chars().count();

    if length == 0 {
        return Err(VaultError::Invalid(
            "имя профиля не может быть пустым".into(),
        ));
    }
    if length > MAX_PROFILE_NAME_LEN {
        return Err(VaultError::Invalid(format!(
            "имя профиля длиннее {MAX_PROFILE_NAME_LEN} символов"
        )));
    }

    Ok(trimmed.to_string())
}

/// Пустая заметка превращается в `None`: иначе в метаданных оседали бы
/// строки из пробелов, а интерфейс показывал бы пустой блок.
fn normalize_note(note: Option<String>) -> Option<String> {
    note.map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
}

impl UnlockedVault {
    /// Профили в порядке добавления.
    pub fn profiles(&self) -> &[ProfileMeta] {
        &self.metadata().profiles
    }

    /// Каталог расшифрованных данных профиля (используется на этапе CryptoFS).
    pub fn temp_profile_dir(&self, profile_id: &str) -> PathBuf {
        self.dir().join(TEMP_DIR).join(profile_id)
    }

    /// Создаёт профиль и сохраняет метаданные на диск.
    pub fn create_profile(
        &mut self,
        name: &str,
        kind: ProfileKind,
        proxy: Option<ProxyConfig>,
        note: Option<String>,
    ) -> Result<ProfileMeta> {
        let profile = ProfileMeta {
            id: uuid::Uuid::new_v4().to_string(),
            name: validate_name(name)?,
            kind,
            // Новое зерно на каждый профиль: два профиля не должны
            // выглядеть для сайтов одинаково.
            seed: ProfileMeta::random_seed(),
            proxy: validate_proxy(proxy)?,
            created_unix: super::unix_now(),
            engine_version: None,
            note: normalize_note(note),
        };
        profile.validate().map_err(VaultError::Invalid)?;

        // Каталог данных создаётся сразу: так структура на диске совпадает
        // с метаданными, а удаление профиля всегда имеет что стирать.
        crate::paths::ensure_dir(&self.profile_dir(&profile.id))?;

        self.metadata_mut().profiles.push(profile.clone());
        if let Err(error) = self.save_metadata() {
            // Откат: метаданные на диске остались прежними, значит и в памяти
            // запись держать нельзя — иначе список профилей разойдётся с файлом.
            self.metadata_mut()
                .profiles
                .retain(|item| item.id != profile.id);
            let _ = fs::remove_dir_all(self.profile_dir(&profile.id));
            return Err(error);
        }

        Ok(profile)
    }

    /// Клонирует профиль: те же настройки, новое зерно отпечатка.
    pub fn clone_profile(
        &mut self,
        source_id: &str,
        new_name: Option<&str>,
    ) -> Result<ProfileMeta> {
        let source = self
            .metadata()
            .find(source_id)
            .cloned()
            .ok_or_else(|| VaultError::NotFound(format!("профиль {source_id}")))?;

        let name = match new_name.map(str::trim).filter(|value| !value.is_empty()) {
            Some(value) => validate_name(value)?,
            None => validate_name(&format!("{} (копия)", source.name))?,
        };

        self.create_profile(
            &name,
            source.kind,
            source.proxy.clone(),
            source.note.clone(),
        )
    }

    /// Меняет имя, тип и заметку профиля.
    pub fn update_profile(
        &mut self,
        id: &str,
        name: &str,
        kind: ProfileKind,
        note: Option<String>,
    ) -> Result<ProfileMeta> {
        let name = validate_name(name)?;

        // Снимок для отката при ошибке записи.
        let previous = self
            .metadata()
            .find(id)
            .cloned()
            .ok_or_else(|| VaultError::NotFound(format!("профиль {id}")))?;

        let note = normalize_note(note);
        {
            let profile = self
                .metadata_mut()
                .find_mut(id)
                .ok_or_else(|| VaultError::NotFound(format!("профиль {id}")))?;
            profile.name = name;
            profile.kind = kind;
            profile.note = note;
        }

        if let Err(error) = self.save_metadata() {
            if let Some(profile) = self.metadata_mut().find_mut(id) {
                profile.name = previous.name;
                profile.kind = previous.kind;
                profile.note = previous.note;
            }
            return Err(error);
        }

        self.metadata()
            .find(id)
            .cloned()
            .ok_or_else(|| VaultError::NotFound(format!("профиль {id}")))
    }

    /// Привязывает прокси к профилю или снимает привязку (`None`).
    pub fn set_proxy(&mut self, id: &str, proxy: Option<ProxyConfig>) -> Result<ProfileMeta> {
        let proxy = validate_proxy(proxy)?;
        let previous = self
            .metadata()
            .find(id)
            .cloned()
            .ok_or_else(|| VaultError::NotFound(format!("профиль {id}")))?;

        {
            let profile = self
                .metadata_mut()
                .find_mut(id)
                .ok_or_else(|| VaultError::NotFound(format!("профиль {id}")))?;
            profile.proxy = proxy;
        }

        if let Err(error) = self.save_metadata() {
            if let Some(profile) = self.metadata_mut().find_mut(id) {
                profile.proxy = previous.proxy;
            }
            return Err(error);
        }

        self.metadata()
            .find(id)
            .cloned()
            .ok_or_else(|| VaultError::NotFound(format!("профиль {id}")))
    }

    /// Удаляет профиль и безвозвратно стирает его данные.
    ///
    /// Порядок важен: сначала стираются данные, потом запись. Если стирание
    /// не удалось, профиль остаётся в списке — пользователь видит ошибку,
    /// а не «профиль исчез, а его файлы остались».
    pub fn delete_profile(&mut self, id: &str) -> Result<ProfileMeta> {
        let index = self
            .metadata()
            .profiles
            .iter()
            .position(|profile| profile.id == id)
            .ok_or_else(|| VaultError::NotFound(format!("профиль {id}")))?;

        let removed = self.metadata().profiles[index].clone();

        wipe_dir(&self.profile_dir(id))?;
        // Расшифрованная копия могла остаться после аварийного завершения.
        wipe_dir(&self.temp_profile_dir(id))?;

        self.metadata_mut().profiles.remove(index);
        if let Err(error) = self.save_metadata() {
            self.metadata_mut().profiles.insert(index, removed.clone());
            return Err(error);
        }

        Ok(removed)
    }
}

/// Проверяет настройки прокси перед сохранением.
fn validate_proxy(proxy: Option<ProxyConfig>) -> Result<Option<ProxyConfig>> {
    if let Some(config) = &proxy {
        config.validate().map_err(VaultError::Invalid)?;
        if config.host.trim() != config.host {
            return Err(VaultError::Invalid(
                "адрес прокси не должен начинаться или заканчиваться пробелом".into(),
            ));
        }
    }
    Ok(proxy)
}

/// Безвозвратно стирает каталог: содержимое перезаписывается случайными
/// байтами, затем удаляется.
///
/// На SSD и в журналируемых файловых системах это **не гарантирует**, что
/// прежние байты исчезли с носителя: контроллер и журнал могут хранить их
/// копии. Настоящую защиту даёт то, что данные профиля лежат на диске
/// зашифрованными, — стирание лишь сокращает окно, в котором расшифрованная
/// копия существовала.
pub fn wipe_dir(dir: &Path) -> Result<()> {
    if !dir.exists() {
        return Ok(());
    }
    wipe_tree(dir)?;
    fs::remove_dir_all(dir)?;
    Ok(())
}

fn wipe_tree(dir: &Path) -> Result<()> {
    for entry in fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();
        let file_type = entry.file_type()?;

        if file_type.is_dir() {
            wipe_tree(&path)?;
        } else if file_type.is_file() {
            wipe_file(&path)?;
        }
        // Символические ссылки и особые файлы не перезаписываем: цель ссылки
        // может находиться вне профиля.
    }
    Ok(())
}

fn wipe_file(path: &Path) -> Result<()> {
    use std::io::Write;

    let length = fs::metadata(path)?.len();
    if length == 0 {
        return Ok(());
    }

    let mut file = fs::OpenOptions::new().write(true).open(path)?;
    let mut left = length;
    while left > 0 {
        let chunk = left.min(64 * 1024) as usize;
        let noise = crypto::random_vec(chunk)?;
        file.write_all(&noise)?;
        left -= chunk as u64;
    }
    file.sync_all()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vault::kdf::KdfParams;
    use crate::vault::metadata::ProxyScheme;
    use crate::vault::session::Vault;

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

    fn proxy() -> ProxyConfig {
        ProxyConfig {
            scheme: ProxyScheme::Socks5,
            host: "gate.example".to_string(),
            port: 1080,
            username: Some("user".to_string()),
            password: Some("secret".to_string()),
        }
    }

    #[test]
    fn create_profile_registers_it_and_makes_directory() {
        let tmp = tempfile::tempdir().unwrap();
        let mut vault = vault(tmp.path());

        let profile = vault
            .create_profile("Рабочий", ProfileKind::Antidetect, None, None)
            .unwrap();

        assert_eq!(vault.profiles().len(), 1);
        assert_eq!(profile.name, "Рабочий");
        assert_ne!(profile.seed, 0, "зерно отпечатка не может быть нулевым");
        assert!(vault.profile_dir(&profile.id).is_dir());
    }

    #[test]
    fn create_profile_survives_reload() {
        let tmp = tempfile::tempdir().unwrap();
        let mut vault = vault(tmp.path());
        let profile = vault
            .create_profile("Постоянный", ProfileKind::Normal, Some(proxy()), None)
            .unwrap();
        vault.lock();

        let unlocked = Vault::open(tmp.path()).unwrap().unlock(PASSWORD).unwrap();
        let stored = unlocked.metadata().find(&profile.id).unwrap();
        assert_eq!(stored.name, "Постоянный");
        assert_eq!(
            stored.proxy.as_ref().unwrap().password.as_deref(),
            Some("secret")
        );
    }

    #[test]
    fn empty_and_overlong_names_are_refused() {
        let tmp = tempfile::tempdir().unwrap();
        let mut vault = vault(tmp.path());

        assert!(matches!(
            vault.create_profile("   ", ProfileKind::Normal, None, None),
            Err(VaultError::Invalid(_))
        ));
        let long = "я".repeat(MAX_PROFILE_NAME_LEN + 1);
        assert!(matches!(
            vault.create_profile(&long, ProfileKind::Normal, None, None),
            Err(VaultError::Invalid(_))
        ));
        assert!(
            vault.profiles().is_empty(),
            "неудачное создание ничего не добавляет"
        );
    }

    #[test]
    fn name_is_trimmed_and_note_emptiness_is_normalized() {
        let tmp = tempfile::tempdir().unwrap();
        let mut vault = vault(tmp.path());

        let profile = vault
            .create_profile(
                "  с пробелами  ",
                ProfileKind::Normal,
                None,
                Some("   ".into()),
            )
            .unwrap();
        assert_eq!(profile.name, "с пробелами");
        assert_eq!(
            profile.note, None,
            "заметка из пробелов должна стать пустой"
        );
    }

    #[test]
    fn invalid_proxy_is_refused() {
        let tmp = tempfile::tempdir().unwrap();
        let mut vault = vault(tmp.path());

        let bad = ProxyConfig { port: 0, ..proxy() };
        assert!(matches!(
            vault.create_profile("Плохой", ProfileKind::Normal, Some(bad), None),
            Err(VaultError::Invalid(_))
        ));
    }

    #[test]
    fn clone_gets_new_id_and_new_seed_but_keeps_settings() {
        let tmp = tempfile::tempdir().unwrap();
        let mut vault = vault(tmp.path());
        let source = vault
            .create_profile(
                "Исходный",
                ProfileKind::Antidetect,
                Some(proxy()),
                Some("заметка".into()),
            )
            .unwrap();

        let clone = vault.clone_profile(&source.id, None).unwrap();

        assert_ne!(clone.id, source.id, "у клона собственный идентификатор");
        assert_ne!(clone.seed, source.seed, "у клона новое зерно отпечатка");
        assert_eq!(clone.kind, source.kind);
        assert_eq!(clone.proxy, source.proxy);
        assert_eq!(clone.note, source.note);
        assert_eq!(clone.name, "Исходный (копия)");
        assert!(vault.profile_dir(&clone.id).is_dir());
        assert_eq!(vault.profiles().len(), 2);
    }

    #[test]
    fn clone_accepts_explicit_name_and_rejects_unknown_source() {
        let tmp = tempfile::tempdir().unwrap();
        let mut vault = vault(tmp.path());
        let source = vault
            .create_profile("Первый", ProfileKind::Normal, None, None)
            .unwrap();

        let clone = vault.clone_profile(&source.id, Some("Второй")).unwrap();
        assert_eq!(clone.name, "Второй");

        assert!(matches!(
            vault.clone_profile("11111111-2222-3333-4444-555555555555", None),
            Err(VaultError::NotFound(_))
        ));
    }

    #[test]
    fn update_profile_changes_fields_and_persists() {
        let tmp = tempfile::tempdir().unwrap();
        let mut vault = vault(tmp.path());
        let profile = vault
            .create_profile("Старое", ProfileKind::Normal, None, None)
            .unwrap();

        let updated = vault
            .update_profile(
                &profile.id,
                "Новое",
                ProfileKind::Antidetect,
                Some("пометка".into()),
            )
            .unwrap();
        assert_eq!(updated.name, "Новое");
        assert_eq!(updated.kind, ProfileKind::Antidetect);
        assert_eq!(updated.note.as_deref(), Some("пометка"));
        vault.lock();

        let unlocked = Vault::open(tmp.path()).unwrap().unlock(PASSWORD).unwrap();
        let stored = unlocked.metadata().find(&profile.id).unwrap();
        assert_eq!(stored.name, "Новое");
        assert_eq!(stored.kind, ProfileKind::Antidetect);
    }

    #[test]
    fn update_and_delete_refuse_unknown_profile() {
        let tmp = tempfile::tempdir().unwrap();
        let mut vault = vault(tmp.path());
        let unknown = "11111111-2222-3333-4444-555555555555";

        assert!(matches!(
            vault.update_profile(unknown, "Имя", ProfileKind::Normal, None),
            Err(VaultError::NotFound(_))
        ));
        assert!(matches!(
            vault.delete_profile(unknown),
            Err(VaultError::NotFound(_))
        ));
    }

    #[test]
    fn set_proxy_attaches_and_clears() {
        let tmp = tempfile::tempdir().unwrap();
        let mut vault = vault(tmp.path());
        let profile = vault
            .create_profile("С прокси", ProfileKind::Normal, None, None)
            .unwrap();

        let attached = vault.set_proxy(&profile.id, Some(proxy())).unwrap();
        assert_eq!(attached.proxy.unwrap().host, "gate.example");

        let cleared = vault.set_proxy(&profile.id, None).unwrap();
        assert!(cleared.proxy.is_none());
    }

    #[test]
    fn delete_removes_record_directories_and_data() {
        let tmp = tempfile::tempdir().unwrap();
        let mut vault = vault(tmp.path());
        let profile = vault
            .create_profile("Удаляемый", ProfileKind::Normal, None, None)
            .unwrap();

        // Положим внутрь файл: он должен исчезнуть вместе с профилем.
        let profile_dir = vault.profile_dir(&profile.id);
        fs::write(profile_dir.join("Cookies"), b"secret-cookie-data").unwrap();

        let temp_dir = vault.temp_profile_dir(&profile.id);
        fs::create_dir_all(&temp_dir).unwrap();
        fs::write(temp_dir.join("Cache"), b"plaintext-cache").unwrap();

        let removed = vault.delete_profile(&profile.id).unwrap();
        assert_eq!(removed.id, profile.id);
        assert!(vault.profiles().is_empty());
        assert!(!profile_dir.exists());
        assert!(
            !temp_dir.exists(),
            "расшифрованная копия стирается вместе с профилем"
        );
    }

    #[test]
    fn delete_keeps_other_profiles_intact() {
        let tmp = tempfile::tempdir().unwrap();
        let mut vault = vault(tmp.path());
        let first = vault
            .create_profile("Первый", ProfileKind::Normal, None, None)
            .unwrap();
        let second = vault
            .create_profile("Второй", ProfileKind::Normal, None, None)
            .unwrap();

        vault.delete_profile(&first.id).unwrap();

        assert_eq!(vault.profiles().len(), 1);
        assert!(vault.profile_dir(&second.id).is_dir());
        assert!(vault.metadata().find(&second.id).is_some());
    }

    #[test]
    fn delete_survives_reload() {
        let tmp = tempfile::tempdir().unwrap();
        let mut vault = vault(tmp.path());
        let profile = vault
            .create_profile("Временный", ProfileKind::Normal, None, None)
            .unwrap();
        vault.delete_profile(&profile.id).unwrap();
        vault.lock();

        let unlocked = Vault::open(tmp.path()).unwrap().unlock(PASSWORD).unwrap();
        assert_eq!(unlocked.metadata().profile_count(), 0);
    }

    #[test]
    fn wipe_dir_erases_file_contents_and_removes_tree() {
        let tmp = tempfile::tempdir().unwrap();
        let target = tmp.path().join("container");
        fs::create_dir_all(target.join("nested")).unwrap();
        fs::write(target.join("a.bin"), vec![7u8; 4096]).unwrap();
        fs::write(target.join("nested").join("b.bin"), vec![9u8; 100]).unwrap();

        wipe_dir(&target).unwrap();

        assert!(!target.exists());
        // Каталог-родитель не тронут: стирается только указанное поддерево.
        assert!(tmp.path().is_dir());
    }

    #[test]
    fn wipe_dir_on_missing_path_is_not_an_error() {
        let tmp = tempfile::tempdir().unwrap();
        assert!(wipe_dir(&tmp.path().join("нет-такого")).is_ok());
    }

    #[test]
    fn validate_name_counts_characters() {
        assert_eq!(validate_name("  Имя  ").unwrap(), "Имя");
        assert!(validate_name(&"я".repeat(MAX_PROFILE_NAME_LEN)).is_ok());
        assert!(validate_name("").is_err());
    }

    #[test]
    fn kind_and_scheme_parse_from_ui_strings() {
        assert_eq!(
            "Normal".parse::<ProfileKind>().unwrap(),
            ProfileKind::Normal
        );
        assert_eq!(
            "ANTIDETECT".parse::<ProfileKind>().unwrap(),
            ProfileKind::Antidetect
        );
        assert!("другой".parse::<ProfileKind>().is_err());

        assert_eq!(
            "SOCKS5".parse::<ProxyScheme>().unwrap(),
            ProxyScheme::Socks5
        );
        assert_eq!("https".parse::<ProxyScheme>().unwrap(), ProxyScheme::Https);
        assert!("ftp".parse::<ProxyScheme>().is_err());
    }
}
