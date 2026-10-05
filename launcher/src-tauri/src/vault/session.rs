//! Хранилище: создание, разблокировка, блокировка.
//!
//! # Раскладка на диске
//!
//! ```text
//! vault/
//!   header.json     открытый заголовок: сигнатура, версия, соль, KDF, verifier
//!   vault.enc       зашифрованные метаданные (профили, прокси, настройки)
//!   attempts.json   открытый счётчик неудачных попыток
//!   profiles/       зашифрованные данные профилей (этап M2)
//!   tmp/            расшифрованные копии на время работы (этап M3)
//! ```
//!
//! Секретов в открытом виде нет нигде. Единственное, что доступно без пароля, —
//! факт существования хранилища, число профилей в нём и число неудачных попыток.

use std::path::{Path, PathBuf};

use zeroize::Zeroizing;

use super::attempts::AttemptsState;
use super::crypto;
use super::error::{Result, VaultError};
use super::header::{self, VaultHeader, VERIFIER_PLAINTEXT};
use super::kdf::{self, KdfParams, KEY_LEN, SALT_LEN};
use super::metadata::VaultMetadata;
use crate::paths;

/// Имя файла заголовка.
pub const HEADER_FILE: &str = "header.json";

/// Имя файла с зашифрованными метаданными.
pub const METADATA_FILE: &str = "vault.enc";

/// Каталог зашифрованных профилей внутри хранилища.
pub const PROFILES_DIR: &str = "profiles";

/// Каталог расшифрованных копий внутри хранилища.
pub const TEMP_DIR: &str = "tmp";

/// Контекст вывода подключей: метаданные.
const INFO_METADATA: &[u8] = b"fousbrowser/v1/metadata";

/// Контекст вывода подключей: данные профиля.
const INFO_PROFILE: &[u8] = b"fousbrowser/v1/profile";

/// Закрытое хранилище: известен только открытый заголовок.
#[derive(Debug, Clone)]
pub struct Vault {
    dir: PathBuf,
    header: VaultHeader,
}

/// Открытое хранилище: мастер-ключ находится в памяти.
///
/// `Debug` реализован вручную и никогда не печатает ключевой материал.
pub struct UnlockedVault {
    dir: PathBuf,
    header: VaultHeader,
    master_key: Zeroizing<[u8; KEY_LEN]>,
    metadata: VaultMetadata,
    dirty: bool,
}

impl std::fmt::Debug for UnlockedVault {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("UnlockedVault")
            .field("dir", &self.dir)
            .field("vault_id", &self.header.vault_id)
            .field("master_key", &"<скрыт>")
            .field("profiles", &self.metadata.profile_count())
            .field("dirty", &self.dirty)
            .finish()
    }
}

impl Vault {
    /// Путь к файлу заголовка.
    pub fn header_path(dir: &Path) -> PathBuf {
        dir.join(HEADER_FILE)
    }

    /// Путь к контейнеру метаданных.
    pub fn metadata_path(dir: &Path) -> PathBuf {
        dir.join(METADATA_FILE)
    }

    /// Существует ли хранилище в указанном каталоге.
    pub fn exists(dir: &Path) -> bool {
        Self::header_path(dir).is_file() && Self::metadata_path(dir).is_file()
    }

    pub fn dir(&self) -> &Path {
        &self.dir
    }

    pub fn header(&self) -> &VaultHeader {
        &self.header
    }

    pub fn vault_id(&self) -> &str {
        &self.header.vault_id
    }

    /// Текущее состояние счётчика неудачных попыток.
    pub fn attempts(&self) -> AttemptsState {
        AttemptsState::load(&self.dir, &self.header.vault_id)
    }

    /// Пользователь подтвердил продолжение попыток после достижения порога.
    ///
    /// Счётчик неудач при этом НЕ обнуляется.
    pub fn confirm_continue(&self) -> Result<()> {
        let mut state = self.attempts();
        state.confirm_continue();
        state.store(&self.dir)
    }

    /// Читает заголовок хранилища с диска.
    pub fn open(dir: &Path) -> Result<Self> {
        let header_path = Self::header_path(dir);
        if !header_path.is_file() {
            return Err(VaultError::NotFound(dir.display().to_string()));
        }
        let bytes = std::fs::read(&header_path)?;
        let header = VaultHeader::from_json(&bytes)?;
        if !Self::metadata_path(dir).is_file() {
            return Err(VaultError::Corrupted(
                "заголовок есть, а контейнера метаданных нет".to_string(),
            ));
        }
        Ok(Self {
            dir: dir.to_path_buf(),
            header,
        })
    }

    /// Создаёт хранилище с параметрами Argon2id по умолчанию.
    pub fn create(dir: &Path, password: &str) -> Result<UnlockedVault> {
        Self::create_with_params(dir, password, KdfParams::default())
    }

    /// Создаёт хранилище с явно заданными параметрами вывода ключа.
    ///
    /// Отдельный вход нужен тестам (дешёвые параметры) и будущему обновлению
    /// параметров KDF без пересоздания хранилища.
    pub fn create_with_params(
        dir: &Path,
        password: &str,
        kdf_params: KdfParams,
    ) -> Result<UnlockedVault> {
        kdf::ensure_acceptable(password)?;
        kdf_params.validate()?;

        if Self::exists(dir) {
            return Err(VaultError::AlreadyExists(dir.display().to_string()));
        }
        paths::ensure_dir(dir)?;
        paths::ensure_dir(&dir.join(PROFILES_DIR))?;
        paths::ensure_dir(&dir.join(TEMP_DIR))?;

        let vault_id = uuid::Uuid::new_v4().to_string();
        let salt = crypto::random_vec(SALT_LEN)?;
        let master_key = kdf::derive_master_key(password, &salt, &kdf_params)?;

        // Заголовок создаётся в два приёма: сначала с пустым verifier,
        // потому что AAD зависит от vault_id и версии формата.
        let mut header = VaultHeader::new(vault_id, kdf_params, &salt, &[]);
        let verifier = crypto::seal(&master_key, &header.verifier_aad(), VERIFIER_PLAINTEXT)?;
        header.verifier_b64 = header::b64_encode(&verifier);
        header.validate()?;
        paths::write_atomic(&Self::header_path(dir), &header.to_json()?)?;

        // Пустые метаданные: предустановленных профилей нет и быть не должно.
        let metadata = VaultMetadata::new();
        let metadata_key = crypto::derive_subkey(
            &master_key,
            header.vault_id.as_bytes(),
            INFO_METADATA,
        )?;
        let plaintext = serde_json::to_vec(&metadata)?;
        let sealed = crypto::seal(&metadata_key, &header.metadata_aad(), &plaintext)?;
        paths::write_atomic(&Self::metadata_path(dir), &sealed)?;

        AttemptsState::new(&header.vault_id).store(dir)?;

        Ok(UnlockedVault {
            dir: dir.to_path_buf(),
            header,
            master_key,
            metadata,
            dirty: false,
        })
    }

    /// Разблокирует хранилище мастер-паролем.
    ///
    /// Порядок действий важен:
    /// 1. проверка подтверждения и паузы;
    /// 2. инкремент счётчика **до** проверки пароля — иначе падение процесса
    ///    во время дорогого вывода ключа не было бы учтено;
    /// 3. вывод ключа и проверка verifier;
    /// 4. только после успеха — расшифровка метаданных и сброс счётчика.
    ///
    /// Ни на одном шаге данные профилей не изменяются и не удаляются.
    pub fn unlock(self, password: &str) -> Result<UnlockedVault> {
        let now = super::unix_now();
        let mut attempts = AttemptsState::load(&self.dir, &self.header.vault_id);

        if attempts.confirm_required {
            return Err(VaultError::ConfirmationRequired {
                attempts: attempts.failed,
            });
        }
        let wait = attempts.remaining_backoff(now);
        if wait > 0 {
            return Err(VaultError::Backoff { seconds: wait });
        }

        attempts.register_failure(now);
        attempts.store(&self.dir)?;

        let salt = self.header.salt()?;
        let master_key = kdf::derive_master_key(password, &salt, &self.header.kdf)?;

        let verifier = self.header.verifier()?;
        if crypto::open(&master_key, &self.header.verifier_aad(), &verifier).is_err() {
            // Единственный случай, когда мы не можем отличить неверный пароль
            // от повреждённого verifier, — и оба трактуются как «пароль не подошёл».
            return Err(VaultError::WrongPassword);
        }

        let metadata_key =
            crypto::derive_subkey(&master_key, self.header.vault_id.as_bytes(), INFO_METADATA)?;
        let sealed = std::fs::read(Self::metadata_path(&self.dir))?;
        let plaintext = crypto::open(&metadata_key, &self.header.metadata_aad(), &sealed)
            .map_err(|_| {
                VaultError::Corrupted(
                    "контейнер метаданных повреждён или был изменён извне".to_string(),
                )
            })?;
        let metadata: VaultMetadata = serde_json::from_slice(&plaintext)?;
        metadata.validate().map_err(VaultError::Corrupted)?;

        // Только теперь, когда пароль доказан, счётчик сбрасывается.
        AttemptsState::new(&self.header.vault_id).store(&self.dir)?;

        Ok(UnlockedVault {
            dir: self.dir,
            header: self.header,
            master_key,
            metadata,
            dirty: false,
        })
    }
}

impl UnlockedVault {
    pub fn dir(&self) -> &Path {
        &self.dir
    }

    pub fn vault_id(&self) -> &str {
        &self.header.vault_id
    }

    pub fn header(&self) -> &VaultHeader {
        &self.header
    }

    pub fn metadata(&self) -> &VaultMetadata {
        &self.metadata
    }

    /// Изменяемые метаданные. После правок нужно вызвать [`Self::save_metadata`].
    pub fn metadata_mut(&mut self) -> &mut VaultMetadata {
        self.dirty = true;
        &mut self.metadata
    }

    pub fn is_dirty(&self) -> bool {
        self.dirty
    }

    /// Подключ для данных указанного профиля.
    pub fn profile_key(&self, profile_id: &str) -> Result<Zeroizing<[u8; KEY_LEN]>> {
        if self.metadata.find(profile_id).is_none() {
            return Err(VaultError::NotFound(format!("профиль {profile_id}")));
        }
        let mut info = Vec::with_capacity(INFO_PROFILE.len() + 1 + profile_id.len());
        info.extend_from_slice(INFO_PROFILE);
        info.push(b'/');
        info.extend_from_slice(profile_id.as_bytes());
        crypto::derive_subkey(&self.master_key, self.header.vault_id.as_bytes(), &info)
    }

    /// AAD для данных указанного профиля.
    pub fn profile_aad(&self, profile_id: &str) -> Vec<u8> {
        self.header.profile_aad(profile_id)
    }

    /// Путь к каталогу зашифрованных данных профиля.
    pub fn profile_dir(&self, profile_id: &str) -> PathBuf {
        self.dir.join(PROFILES_DIR).join(profile_id)
    }

    /// Шифрует и записывает метаданные на диск атомарно.
    pub fn save_metadata(&mut self) -> Result<()> {
        self.metadata.validate().map_err(VaultError::Corrupted)?;
        let key =
            crypto::derive_subkey(&self.master_key, self.header.vault_id.as_bytes(), INFO_METADATA)?;
        let plaintext = serde_json::to_vec(&self.metadata)?;
        let sealed = crypto::seal(&key, &self.header.metadata_aad(), &plaintext)?;
        paths::write_atomic(&Vault::metadata_path(&self.dir), &sealed)?;
        self.dirty = false;
        Ok(())
    }

    /// Явная блокировка: мастер-ключ затирается в памяти.
    ///
    /// То же произойдёт и при обычном `drop`, но явный вызов делает намерение
    /// очевидным в коде обработчиков и в тестах.
    pub fn lock(self) {
        drop(self);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vault::metadata::{ProfileKind, ProfileMeta, ProxyConfig, ProxyScheme};

    /// Дешёвые параметры Argon2id: тесты не должны занимать 256 МиБ на вызов.
    fn cheap() -> KdfParams {
        KdfParams {
            algorithm: "argon2id".to_string(),
            m_cost_kib: 64,
            t_cost: 1,
            p_cost: 1,
        }
    }

    fn create(dir: &Path, password: &str) -> UnlockedVault {
        Vault::create_with_params(dir, password, cheap()).unwrap()
    }

    /// «Проматывает» нарастающую задержку, как если бы пользователь её переждал.
    ///
    /// Нужно тестам, потому что задержка проверяется ДО пароля: после пяти
    /// неудач даже верный ввод обязан подождать. Обнуление времени последней
    /// неудачи эквивалентно «прошло достаточно времени».
    fn wait_out_backoff(dir: &Path) {
        let opened = Vault::open(dir).unwrap();
        let mut state = opened.attempts();
        state.last_failed_unix = 0;
        state.store(dir).unwrap();
    }

    const PASSWORD: &str = "correct-horse-battery";

    #[test]
    fn create_produces_expected_files() {
        let tmp = tempfile::tempdir().unwrap();
        let vault = create(tmp.path(), PASSWORD);
        assert!(!vault.is_dirty());

        assert!(Vault::header_path(tmp.path()).is_file());
        assert!(Vault::metadata_path(tmp.path()).is_file());
        assert!(AttemptsState::path_in(tmp.path()).is_file());
        assert!(tmp.path().join(PROFILES_DIR).is_dir());
        assert!(tmp.path().join(TEMP_DIR).is_dir());
    }

    #[test]
    fn create_refuses_existing_vault() {
        let tmp = tempfile::tempdir().unwrap();
        create(tmp.path(), PASSWORD);
        assert!(matches!(
            Vault::create_with_params(tmp.path(), "another-password-1", cheap()),
            Err(VaultError::AlreadyExists(_))
        ));
    }

    #[test]
    fn create_rejects_short_password() {
        let tmp = tempfile::tempdir().unwrap();
        assert!(matches!(
            Vault::create_with_params(tmp.path(), "short", cheap()),
            Err(VaultError::WeakPassword(_))
        ));
        assert!(!Vault::exists(tmp.path()), "неудачное создание не должно оставлять файлов");
    }

    #[test]
    fn unlock_with_correct_password_succeeds() {
        let tmp = tempfile::tempdir().unwrap();
        let created = create(tmp.path(), PASSWORD);
        let vault_id = created.vault_id().to_string();
        created.lock();

        let opened = Vault::open(tmp.path()).unwrap();
        let unlocked = opened.unlock(PASSWORD).unwrap();
        assert_eq!(unlocked.vault_id(), vault_id);
        assert_eq!(unlocked.metadata().profile_count(), 0);
    }

    #[test]
    fn wrong_password_is_rejected_and_counter_grows() {
        let tmp = tempfile::tempdir().unwrap();
        create(tmp.path(), PASSWORD).lock();

        for expected in 1..=3u32 {
            let opened = Vault::open(tmp.path()).unwrap();
            assert!(matches!(
                opened.unlock("definitely-wrong-password"),
                Err(VaultError::WrongPassword)
            ));
            let state = Vault::open(tmp.path()).unwrap().attempts();
            assert_eq!(state.failed, expected);
        }
    }

    /// Главный тест политики: неудачные попытки не должны ничего удалять.
    #[test]
    fn failed_attempts_never_destroy_data() {
        let tmp = tempfile::tempdir().unwrap();
        create(tmp.path(), PASSWORD).lock();

        let header_before = std::fs::read(Vault::header_path(tmp.path())).unwrap();
        let metadata_before = std::fs::read(Vault::metadata_path(tmp.path())).unwrap();

        for _ in 0..30 {
            let opened = Vault::open(tmp.path()).unwrap();
            let _ = opened.unlock("wrong-password-attempt");
        }

        assert_eq!(
            std::fs::read(Vault::header_path(tmp.path())).unwrap(),
            header_before
        );
        assert_eq!(
            std::fs::read(Vault::metadata_path(tmp.path())).unwrap(),
            metadata_before
        );

        // и верный пароль по-прежнему работает — после того, как задержка истекла
        wait_out_backoff(tmp.path());
        let unlocked = Vault::open(tmp.path()).unwrap().unlock(PASSWORD).unwrap();
        assert_eq!(unlocked.metadata().profile_count(), 0);
    }

    #[test]
    fn successful_unlock_resets_counter() {
        let tmp = tempfile::tempdir().unwrap();
        create(tmp.path(), PASSWORD).lock();

        for _ in 0..3 {
            let _ = Vault::open(tmp.path()).unwrap().unlock("wrong-password-attempt");
        }
        assert_eq!(Vault::open(tmp.path()).unwrap().attempts().failed, 3);

        let _ = Vault::open(tmp.path()).unwrap().unlock(PASSWORD).unwrap();
        assert_eq!(Vault::open(tmp.path()).unwrap().attempts().failed, 0);
    }

    #[test]
    fn backoff_starts_after_five_failures() {
        let tmp = tempfile::tempdir().unwrap();
        create(tmp.path(), PASSWORD).lock();

        for _ in 0..5 {
            let _ = Vault::open(tmp.path()).unwrap().unlock("wrong-password-attempt");
        }

        let opened = Vault::open(tmp.path()).unwrap();
        match opened.unlock("wrong-password-attempt") {
            Err(VaultError::Backoff { seconds }) => assert!(seconds > 0),
            other => panic!("ожидалась пауза, получено: {other:?}"),
        }
    }

    #[test]
    fn hundred_failures_require_confirmation_but_keep_data() {
        let tmp = tempfile::tempdir().unwrap();
        create(tmp.path(), PASSWORD).lock();

        // Прогоняем счётчик напрямую: 100 полных выводов ключа в тестах избыточны.
        // Состояние соответствует ровно 100 неудачным попыткам ПОДРЯД — тогда
        // счётчик и выставляет confirm_required.
        let opened = Vault::open(tmp.path()).unwrap();
        let mut state = opened.attempts();
        state.failed = super::super::attempts::MAX_ATTEMPTS_BEFORE_CONFIRMATION;
        state.confirm_required = true;
        state.store(tmp.path()).unwrap();

        let opened = Vault::open(tmp.path()).unwrap();
        assert!(matches!(
            opened.unlock(PASSWORD),
            Err(VaultError::ConfirmationRequired { .. })
        ));

        // данные на месте, и после подтверждения верный пароль работает
        assert!(Vault::metadata_path(tmp.path()).is_file());
        Vault::open(tmp.path()).unwrap().confirm_continue().unwrap();
        wait_out_backoff(tmp.path());
        let unlocked = Vault::open(tmp.path()).unwrap().unlock(PASSWORD).unwrap();
        assert_eq!(unlocked.vault_id().len(), 36);
    }

    /// Порог — ровно 100 неудач ПОДРЯД. На 99-й неудаче верный пароль ещё
    /// проходит и сбрасывает счётчик: одна опечатка не должна приводить
    /// к появлению экрана подтверждения.
    #[test]
    fn ninetynine_failures_then_correct_password_still_unlocks() {
        let tmp = tempfile::tempdir().unwrap();
        create(tmp.path(), PASSWORD).lock();

        let opened = Vault::open(tmp.path()).unwrap();
        let mut state = opened.attempts();
        state.failed = super::super::attempts::MAX_ATTEMPTS_BEFORE_CONFIRMATION - 1;
        state.confirm_required = false;
        state.last_failed_unix = 0;
        state.store(tmp.path()).unwrap();

        let unlocked = Vault::open(tmp.path()).unwrap().unlock(PASSWORD).unwrap();
        assert_eq!(unlocked.metadata().profile_count(), 0);
        assert_eq!(
            Vault::open(tmp.path()).unwrap().attempts().failed,
            0,
            "успешный вход сбрасывает счётчик даже на 99-й попытке"
        );
    }

    #[test]
    fn metadata_survives_save_and_reload() {
        let tmp = tempfile::tempdir().unwrap();
        let mut vault = create(tmp.path(), PASSWORD);

        let id = uuid::Uuid::new_v4().to_string();
        vault.metadata_mut().profiles.push(ProfileMeta {
            id: id.clone(),
            name: "Основной".to_string(),
            kind: ProfileKind::Antidetect,
            seed: 12345,
            proxy: Some(ProxyConfig {
                scheme: ProxyScheme::Socks5,
                host: "gate.example".to_string(),
                port: 1080,
                username: Some("user".to_string()),
                password: Some("proxy-secret".to_string()),
            }),
            created_unix: 1_700_000_000,
            engine_version: None,
            note: Some("заметка".to_string()),
        });
        assert!(vault.is_dirty());
        vault.save_metadata().unwrap();
        assert!(!vault.is_dirty());
        vault.lock();

        let unlocked = Vault::open(tmp.path()).unwrap().unlock(PASSWORD).unwrap();
        assert_eq!(unlocked.metadata().profile_count(), 1);
        let profile = unlocked.metadata().find(&id).unwrap();
        assert_eq!(profile.kind, ProfileKind::Antidetect);
        assert_eq!(profile.seed, 12345);
        assert_eq!(
            profile.proxy.as_ref().unwrap().password.as_deref(),
            Some("proxy-secret")
        );
    }

    #[test]
    fn metadata_on_disk_leaks_no_profile_names() {
        let tmp = tempfile::tempdir().unwrap();
        let mut vault = create(tmp.path(), PASSWORD);
        vault.metadata_mut().profiles.push(ProfileMeta {
            id: uuid::Uuid::new_v4().to_string(),
            name: "Секретное-имя-профиля".to_string(),
            kind: ProfileKind::Normal,
            seed: 1,
            proxy: None,
            created_unix: 0,
            engine_version: None,
            note: None,
        });
        vault.save_metadata().unwrap();
        vault.lock();

        let raw = std::fs::read(Vault::metadata_path(tmp.path())).unwrap();
        let haystack = String::from_utf8_lossy(&raw);
        assert!(!haystack.contains("Секретное"), "имя профиля не должно быть видно");
        assert!(!haystack.contains("\"profiles\""), "структура не должна быть видна");

        // открытый индекс хранит только идентификаторы
        let header = std::fs::read_to_string(Vault::header_path(tmp.path())).unwrap();
        assert!(!header.contains("Секретное"));
    }

    #[test]
    fn tampered_metadata_container_is_detected() {
        let tmp = tempfile::tempdir().unwrap();
        create(tmp.path(), PASSWORD).lock();

        let path = Vault::metadata_path(tmp.path());
        let mut bytes = std::fs::read(&path).unwrap();
        let last = bytes.len() - 1;
        bytes[last] ^= 0x01;
        std::fs::write(&path, &bytes).unwrap();

        let err = Vault::open(tmp.path()).unwrap().unlock(PASSWORD);
        assert!(matches!(err, Err(VaultError::Corrupted(_))));
    }

    #[test]
    fn foreign_vault_header_is_rejected() {
        let tmp = tempfile::tempdir().unwrap();
        create(tmp.path(), PASSWORD).lock();
        let path = Vault::header_path(tmp.path());
        let mut header: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
        header["magic"] = serde_json::Value::String("OTHER-VAULT".to_string());
        std::fs::write(&path, serde_json::to_vec(&header).unwrap()).unwrap();

        assert!(Vault::open(tmp.path()).is_err());
    }

    #[test]
    fn missing_vault_reports_not_found() {
        let tmp = tempfile::tempdir().unwrap();
        assert!(matches!(
            Vault::open(tmp.path()),
            Err(VaultError::NotFound(_))
        ));
    }

    #[test]
    fn profile_keys_are_unique_per_profile() {
        let tmp = tempfile::tempdir().unwrap();
        let mut vault = create(tmp.path(), PASSWORD);

        let first = uuid::Uuid::new_v4().to_string();
        let second = uuid::Uuid::new_v4().to_string();
        for id in [&first, &second] {
            vault.metadata_mut().profiles.push(ProfileMeta {
                id: id.clone(),
                name: id.clone(),
                kind: ProfileKind::Normal,
                seed: 7,
                proxy: None,
                created_unix: 0,
                engine_version: None,
                note: None,
            });
        }

        let key_a = vault.profile_key(&first).unwrap();
        let key_b = vault.profile_key(&second).unwrap();
        assert_ne!(&key_a[..], &key_b[..]);
        assert_ne!(vault.profile_aad(&first), vault.profile_aad(&second));

        // одного профиля ключ стабилен между вызовами
        assert_eq!(&key_a[..], &vault.profile_key(&first).unwrap()[..]);
    }

    #[test]
    fn profile_key_for_unknown_profile_is_refused() {
        let tmp = tempfile::tempdir().unwrap();
        let vault = create(tmp.path(), PASSWORD);
        assert!(matches!(
            vault.profile_key("11111111-2222-3333-4444-555555555555"),
            Err(VaultError::NotFound(_))
        ));
    }

    #[test]
    fn debug_output_hides_key_material() {
        let tmp = tempfile::tempdir().unwrap();
        let vault = create(tmp.path(), PASSWORD);
        let rendered = format!("{vault:?}");
        assert!(rendered.contains("<скрыт>"));
        assert!(!rendered.contains(&format!("{:?}", vault.master_key)));
    }
}
