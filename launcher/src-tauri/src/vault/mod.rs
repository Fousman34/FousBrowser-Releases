//! Шифрованное хранилище FousBrowser.
//!
//! # Что защищается
//!
//! Мастер-пароль → Argon2id → мастер-ключ → HKDF → подключи:
//!
//! - подключ метаданных шифрует `vault.enc` (профили, прокси, настройки);
//! - отдельный подключ на каждый профиль шифрует его данные.
//!
//! Ни один секрет не хранится в открытом виде. Индивидуальная соль и
//! параметры Argon2id лежат в открытом заголовке — это не тайна.
//!
//! # Границы
//!
//! Хранилище защищает данные **на диске**: кражу ноутбука, чужой доступ
//! к файлам, облачные резервные копии. Оно не защищает от вредоносного кода
//! в сессии пользователя, от клавиатурных шпионов и от того, что во время
//! работы браузера профиль расшифрован. Подробности — в `docs/THREAT-MODEL.md`.
//!
//! # Чего здесь принципиально нет
//!
//! Автоудаления данных по числу неудачных попыток ввода пароля. Такого кода
//! нет и не должно появиться: см. документацию модуля [`attempts`].

pub mod attempts;
pub mod crypto;
pub mod error;
pub mod header;
pub mod kdf;
pub mod metadata;
pub mod session;

// Короткие имена для часто используемых типов.
pub use attempts::{AttemptsState, MAX_ATTEMPTS_BEFORE_CONFIRMATION, WARN_AT_ATTEMPTS};
pub use error::{Result, VaultError};
pub use header::VaultHeader;
pub use kdf::{check_password, KdfParams, PasswordReport};
pub use metadata::{
    OrphanPolicy, ProfileKind, ProfileMeta, ProxyConfig, ProxyScheme, Settings, VaultMetadata,
};
pub use session::{UnlockedVault, Vault};

use std::time::{SystemTime, UNIX_EPOCH};

/// Текущее время в секундах от начала эпохи Unix.
///
/// Если системные часы сбиты на момент до 1970 года, возвращается 0 —
/// это безопаснее паники и не влияет на криптографию.
pub fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|elapsed| elapsed.as_secs())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unix_now_is_plausible() {
        // 2020-01-01 — раньше этого времени тесты не запускаются
        assert!(unix_now() > 1_577_836_800);
    }
}
