//! Метаданные хранилища: список профилей, прокси, настройки.
//!
//! Всё содержимое этого модуля живёт только внутри зашифрованного контейнера
//! `vault.enc`. В открытом виде на диске нет ни имён профилей, ни адресов
//! и паролей прокси.

use serde::{Deserialize, Serialize};

/// Версия схемы метаданных.
pub const METADATA_SCHEMA_VERSION: u32 = 1;

/// Максимальная длина имени профиля в символах.
pub const MAX_PROFILE_NAME_LEN: usize = 64;

/// Тип профиля.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ProfileKind {
    /// Стоковый Chromium без патчей — повседневный сёрфинг.
    Normal,
    /// Chromium с патчами подмены fingerprint.
    Antidetect,
}

impl ProfileKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Normal => "normal",
            Self::Antidetect => "antidetect",
        }
    }

    /// Требует ли тип профиля патченный движок.
    pub fn requires_patched_engine(&self) -> bool {
        matches!(self, Self::Antidetect)
    }
}

/// Разбор типа профиля из строки интерфейса.
///
/// Регистр не важен: фронтенд может присылать как `normal`, так и `Normal`.
impl std::str::FromStr for ProfileKind {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value.trim().to_ascii_lowercase().as_str() {
            "normal" => Ok(Self::Normal),
            "antidetect" => Ok(Self::Antidetect),
            other => Err(format!(
                "неизвестный тип профиля: {other} (ожидается normal или antidetect)"
            )),
        }
    }
}

/// Схема прокси.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ProxyScheme {
    Socks5,
    Http,
    Https,
}

impl ProxyScheme {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Socks5 => "socks5",
            Self::Http => "http",
            Self::Https => "https",
        }
    }

    pub fn default_port(&self) -> u16 {
        match self {
            Self::Socks5 => 1080,
            Self::Http | Self::Https => 8080,
        }
    }
}

/// Разбор схемы прокси из строки интерфейса.
impl std::str::FromStr for ProxyScheme {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value.trim().to_ascii_lowercase().as_str() {
            "socks5" | "socks" => Ok(Self::Socks5),
            "http" => Ok(Self::Http),
            "https" => Ok(Self::Https),
            other => Err(format!(
                "неизвестная схема прокси: {other} (ожидается socks5, http или https)"
            )),
        }
    }
}

/// Настройки прокси профиля.
///
/// Пароль хранится внутри зашифрованного контейнера. Утечки через список
/// процессов не происходит ещё и потому, что движку передаётся адрес
/// локального прокси-моста, а не этого прокси.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProxyConfig {
    pub scheme: ProxyScheme,
    pub host: String,
    pub port: u16,
    pub username: Option<String>,
    pub password: Option<String>,
}

impl ProxyConfig {
    /// Адрес вида `host:port` — то, что уходит в `--proxy-server` моста.
    pub fn endpoint(&self) -> String {
        format!("{}:{}", self.host, self.port)
    }

    /// Требуется ли авторизация на прокси.
    pub fn has_auth(&self) -> bool {
        self.username.as_deref().is_some_and(|u| !u.is_empty())
    }

    pub fn validate(&self) -> Result<(), String> {
        if self.host.trim().is_empty() {
            return Err("адрес прокси не может быть пустым".to_string());
        }
        if self.host.contains(char::is_whitespace) {
            return Err("адрес прокси не должен содержать пробелов".to_string());
        }
        if self.port == 0 {
            return Err("порт прокси не может быть нулевым".to_string());
        }
        if self.password.is_some() && !self.has_auth() {
            return Err("пароль прокси задан без имени пользователя".to_string());
        }
        Ok(())
    }
}

/// Метаданные одного профиля.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProfileMeta {
    /// UUID профиля. Используется в путях и в AAD: переименовать нельзя.
    pub id: String,
    pub name: String,
    pub kind: ProfileKind,
    /// Зерно fingerprint. При клонировании профиля всегда генерируется новое.
    pub seed: u32,
    pub proxy: Option<ProxyConfig>,
    pub created_unix: u64,
    /// Версия движка, на которой профиль запускался в последний раз.
    pub engine_version: Option<String>,
    pub note: Option<String>,
}

impl ProfileMeta {
    pub fn validate(&self) -> Result<(), String> {
        if uuid::Uuid::parse_str(&self.id).is_err() {
            return Err(format!(
                "идентификатор профиля не является UUID: {}",
                self.id
            ));
        }
        let name_len = self.name.chars().count();
        if name_len == 0 {
            return Err("имя профиля не может быть пустым".to_string());
        }
        if name_len > MAX_PROFILE_NAME_LEN {
            return Err(format!(
                "имя профиля длиннее {MAX_PROFILE_NAME_LEN} символов"
            ));
        }
        if let Some(proxy) = &self.proxy {
            proxy.validate()?;
        }
        Ok(())
    }

    /// Новое зерно для клона: 32-битное, ненулевое.
    pub fn random_seed() -> u32 {
        // Ошибка генератора здесь означала бы, что система неработоспособна,
        // поэтому берём заведомо ненулевой запасной вариант.
        let seed = super::crypto::random_bytes::<4>()
            .map(u32::from_le_bytes)
            .unwrap_or(0x5A5A_5A5A);
        if seed == 0 {
            1
        } else {
            seed
        }
    }
}

/// Что делать с расшифрованной папкой, оставшейся после аварийного завершения.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum OrphanPolicy {
    /// Зашифровать обратно (поведение по умолчанию — данные не теряются).
    #[default]
    EncryptBack,
    /// Удалить расшифрованную копию.
    Delete,
}

/// Настройки лаунчера.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Settings {
    pub check_updates_on_start: bool,
    /// Интервал проверки обновлений в часах.
    pub update_interval_hours: u32,
    pub orphan_policy: OrphanPolicy,
    /// Автоблокировка по неактивности в минутах; 0 — выключена.
    pub auto_lock_minutes: u32,
    /// Напоминать об экспорте шифрованного бэкапа.
    pub remind_backup: bool,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            check_updates_on_start: true,
            // Интервал не кратен суткам: так клиенты не синхронизируются
            // в общий пик нагрузки на сервер обновлений.
            update_interval_hours: 6,
            orphan_policy: OrphanPolicy::EncryptBack,
            auto_lock_minutes: 15,
            remind_backup: true,
        }
    }
}

impl Settings {
    pub fn validate(&self) -> Result<(), String> {
        if self.update_interval_hours == 0 || self.update_interval_hours > 168 {
            return Err("интервал проверки обновлений должен быть от 1 до 168 часов".to_string());
        }
        if self.auto_lock_minutes > 24 * 60 {
            return Err("автоблокировка не может превышать 24 часа".to_string());
        }
        Ok(())
    }
}

/// Корневой объект зашифрованных метаданных.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VaultMetadata {
    pub schema_version: u32,
    pub profiles: Vec<ProfileMeta>,
    pub settings: Settings,
}

impl Default for VaultMetadata {
    fn default() -> Self {
        Self::new()
    }
}

impl VaultMetadata {
    pub fn new() -> Self {
        Self {
            schema_version: METADATA_SCHEMA_VERSION,
            profiles: Vec::new(),
            settings: Settings::default(),
        }
    }

    pub fn find(&self, id: &str) -> Option<&ProfileMeta> {
        self.profiles.iter().find(|profile| profile.id == id)
    }

    pub fn find_mut(&mut self, id: &str) -> Option<&mut ProfileMeta> {
        self.profiles.iter_mut().find(|profile| profile.id == id)
    }

    pub fn profile_count(&self) -> usize {
        self.profiles.len()
    }

    /// Проверка целостности после расшифровки.
    pub fn validate(&self) -> Result<(), String> {
        if self.schema_version > METADATA_SCHEMA_VERSION {
            return Err(format!(
                "схема метаданных версии {} новее, чем поддерживает эта сборка ({})",
                self.schema_version, METADATA_SCHEMA_VERSION
            ));
        }
        self.settings.validate()?;
        for profile in &self.profiles {
            profile.validate()?;
        }
        // Идентификаторы обязаны быть уникальными, иначе AAD профилей совпадёт.
        for (index, profile) in self.profiles.iter().enumerate() {
            if self.profiles[index + 1..]
                .iter()
                .any(|other| other.id == profile.id)
            {
                return Err(format!(
                    "повторяющийся идентификатор профиля: {}",
                    profile.id
                ));
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn profile(id: &str, name: &str) -> ProfileMeta {
        ProfileMeta {
            id: id.to_string(),
            name: name.to_string(),
            kind: ProfileKind::Normal,
            seed: 42,
            proxy: None,
            created_unix: 0,
            engine_version: None,
            note: None,
        }
    }

    const UUID_A: &str = "11111111-2222-3333-4444-555555555555";

    #[test]
    fn metadata_roundtrip_through_json() {
        let mut metadata = VaultMetadata::new();
        metadata.profiles.push(ProfileMeta {
            proxy: Some(ProxyConfig {
                scheme: ProxyScheme::Socks5,
                host: "127.0.0.1".to_string(),
                port: 1080,
                username: Some("user".to_string()),
                password: Some("secret".to_string()),
            }),
            kind: ProfileKind::Antidetect,
            ..profile(UUID_A, "Рабочий")
        });

        let json = serde_json::to_vec(&metadata).unwrap();
        let restored: VaultMetadata = serde_json::from_slice(&json).unwrap();
        assert_eq!(restored, metadata);
        assert!(restored.validate().is_ok());
    }

    #[test]
    fn profile_kind_serializes_lowercase() {
        assert_eq!(
            serde_json::to_string(&ProfileKind::Normal).unwrap(),
            "\"normal\""
        );
        assert_eq!(
            serde_json::to_string(&ProfileKind::Antidetect).unwrap(),
            "\"antidetect\""
        );
    }

    #[test]
    fn only_antidetect_requires_patched_engine() {
        assert!(!ProfileKind::Normal.requires_patched_engine());
        assert!(ProfileKind::Antidetect.requires_patched_engine());
    }

    #[test]
    fn duplicate_profile_ids_are_rejected() {
        let mut metadata = VaultMetadata::new();
        metadata.profiles.push(profile(UUID_A, "один"));
        metadata.profiles.push(profile(UUID_A, "два"));
        assert!(metadata.validate().is_err());
    }

    #[test]
    fn invalid_profile_id_is_rejected() {
        let mut metadata = VaultMetadata::new();
        metadata.profiles.push(profile("не-uuid", "имя"));
        assert!(metadata.validate().is_err());
    }

    #[test]
    fn empty_and_overlong_names_are_rejected() {
        let mut metadata = VaultMetadata::new();
        metadata.profiles.push(profile(UUID_A, ""));
        assert!(metadata.validate().is_err());

        let mut metadata = VaultMetadata::new();
        metadata
            .profiles
            .push(profile(UUID_A, &"я".repeat(MAX_PROFILE_NAME_LEN + 1)));
        assert!(metadata.validate().is_err());
    }

    #[test]
    fn name_length_counts_characters_not_bytes() {
        let mut metadata = VaultMetadata::new();
        metadata
            .profiles
            .push(profile(UUID_A, &"я".repeat(MAX_PROFILE_NAME_LEN)));
        assert!(
            metadata.validate().is_ok(),
            "64 кириллических символа — допустимо"
        );
    }

    #[test]
    fn proxy_validation() {
        let base = ProxyConfig {
            scheme: ProxyScheme::Http,
            host: "proxy.example".to_string(),
            port: 8080,
            username: None,
            password: None,
        };
        assert!(base.validate().is_ok());
        assert_eq!(base.endpoint(), "proxy.example:8080");
        assert!(!base.has_auth());

        let empty_host = ProxyConfig {
            host: "  ".to_string(),
            ..base.clone()
        };
        assert!(empty_host.validate().is_err());

        let zero_port = ProxyConfig {
            port: 0,
            ..base.clone()
        };
        assert!(zero_port.validate().is_err());

        let password_without_user = ProxyConfig {
            password: Some("secret".to_string()),
            ..base
        };
        assert!(password_without_user.validate().is_err());
    }

    #[test]
    fn proxy_default_ports_match_scheme() {
        assert_eq!(ProxyScheme::Socks5.default_port(), 1080);
        assert_eq!(ProxyScheme::Http.default_port(), 8080);
        assert_eq!(ProxyScheme::Https.default_port(), 8080);
    }

    #[test]
    fn default_settings_are_valid() {
        assert!(Settings::default().validate().is_ok());
        assert_eq!(Settings::default().orphan_policy, OrphanPolicy::EncryptBack);
    }

    #[test]
    fn settings_bounds_are_enforced() {
        assert!(Settings {
            update_interval_hours: 0,
            ..Settings::default()
        }
        .validate()
        .is_err());
        assert!(Settings {
            update_interval_hours: 200,
            ..Settings::default()
        }
        .validate()
        .is_err());
        assert!(Settings {
            auto_lock_minutes: 24 * 60 + 1,
            ..Settings::default()
        }
        .validate()
        .is_err());
        assert!(
            Settings {
                auto_lock_minutes: 0,
                ..Settings::default()
            }
            .validate()
            .is_ok(),
            "0 минут — автоблокировка выключена"
        );
    }

    #[test]
    fn newer_schema_is_refused() {
        let metadata = VaultMetadata {
            schema_version: METADATA_SCHEMA_VERSION + 1,
            ..VaultMetadata::new()
        };
        assert!(metadata.validate().is_err());
    }

    #[test]
    fn random_seed_is_nonzero() {
        for _ in 0..64 {
            assert_ne!(ProfileMeta::random_seed(), 0);
        }
    }
}
