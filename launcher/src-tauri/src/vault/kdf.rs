//! Вывод ключа шифрования из мастер-пароля (Argon2id).
//!
//! Мастер-пароль не хранится ни в каком виде. Параметры KDF и соль лежат
//! в открытом заголовке хранилища — это не секрет, но позволяет менять
//! параметры между версиями без потери совместимости.

use argon2::{Algorithm, Argon2, Params, Version};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use super::error::{Result, VaultError};

/// Длина мастер-ключа и всех производных ключей.
pub const KEY_LEN: usize = 32;

/// Длина соли Argon2id.
pub const SALT_LEN: usize = 16;

/// Минимальная длина мастер-пароля по требованиям проекта.
pub const MIN_PASSWORD_LEN: usize = 12;

/// 256 МиБ памяти. Компромисс между стойкостью и временем разблокировки
/// (порядка 0,5–1,5 с на типичной машине).
pub const DEFAULT_M_COST_KIB: u32 = 256 * 1024;
pub const DEFAULT_T_COST: u32 = 3;
pub const DEFAULT_P_COST: u32 = 4;

/// Параметры вывода ключа, сохраняемые в заголовке хранилища.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KdfParams {
    /// Всегда `"argon2id"`. Строка, а не enum, чтобы читать чужие заголовки
    /// и выдавать понятную ошибку вместо паники.
    pub algorithm: String,
    /// Память в КиБ.
    pub m_cost_kib: u32,
    /// Число итераций.
    pub t_cost: u32,
    /// Степень параллелизма.
    pub p_cost: u32,
}

impl Default for KdfParams {
    fn default() -> Self {
        Self {
            algorithm: "argon2id".to_string(),
            m_cost_kib: DEFAULT_M_COST_KIB,
            t_cost: DEFAULT_T_COST,
            p_cost: DEFAULT_P_COST,
        }
    }
}

impl KdfParams {
    /// Проверяет, что параметры вообще пригодны к использованию.
    pub fn validate(&self) -> Result<()> {
        if self.algorithm != "argon2id" {
            return Err(VaultError::Corrupted(format!(
                "неподдерживаемый алгоритм вывода ключа: {}",
                self.algorithm
            )));
        }
        // Argon2 требует минимум 8 блоков на поток.
        if self.m_cost_kib < 8 * self.p_cost.max(1) {
            return Err(VaultError::Corrupted(
                "слишком мало памяти для Argon2id".to_string(),
            ));
        }
        if self.t_cost == 0 {
            return Err(VaultError::Corrupted(
                "число итераций Argon2id должно быть больше нуля".to_string(),
            ));
        }
        if self.p_cost == 0 {
            return Err(VaultError::Corrupted(
                "степень параллелизма Argon2id должна быть больше нуля".to_string(),
            ));
        }
        Ok(())
    }

    fn instance(&self) -> Result<Argon2<'static>> {
        self.validate()?;
        let params = Params::new(
            self.m_cost_kib,
            self.t_cost,
            self.p_cost,
            Some(KEY_LEN),
        )
        .map_err(|_| VaultError::Corrupted("некорректные параметры Argon2id".to_string()))?;
        Ok(Argon2::new(Algorithm::Argon2id, Version::V0x13, params))
    }
}

/// Выводит мастер-ключ из пароля и соли.
///
/// Возвращаемый ключ обёрнут в [`Zeroizing`] и будет затёрт в памяти
/// при уничтожении.
pub fn derive_master_key(
    password: &str,
    salt: &[u8],
    params: &KdfParams,
) -> Result<Zeroizing<[u8; KEY_LEN]>> {
    if salt.len() < argon2::MIN_SALT_LEN {
        return Err(VaultError::Corrupted(format!(
            "соль короче минимума Argon2 ({} байт)",
            argon2::MIN_SALT_LEN
        )));
    }

    let argon2 = params.instance()?;
    let mut key = Zeroizing::new([0u8; KEY_LEN]);
    argon2
        .hash_password_into(password.as_bytes(), salt, &mut key[..])
        .map_err(|_| VaultError::Crypto("не удалось вывести ключ из пароля"))?;
    Ok(key)
}

/// Оценка мастер-пароля для интерфейса.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PasswordReport {
    /// Длина в символах (не в байтах).
    pub length: usize,
    pub min_length: usize,
    /// Пароль достаточной длины — единственное жёсткое требование.
    pub acceptable: bool,
    pub has_lowercase: bool,
    pub has_uppercase: bool,
    pub has_digit: bool,
    pub has_symbol: bool,
    /// 0..=4, для индикатора в интерфейсе.
    pub score: u8,
    /// Рекомендации (не блокируют создание хранилища).
    pub recommendations: Vec<String>,
}

impl PasswordReport {
    /// Есть ли хоть одно не выполненное пожелание к составу пароля.
    pub fn has_recommendations(&self) -> bool {
        !self.recommendations.is_empty()
    }
}

/// Проверяет пароль: жёстко требуется только длина, состав — рекомендация.
pub fn check_password(password: &str) -> PasswordReport {
    let length = password.chars().count();
    let has_lowercase = password.chars().any(|c| c.is_lowercase());
    let has_uppercase = password.chars().any(|c| c.is_uppercase());
    let has_digit = password.chars().any(|c| c.is_ascii_digit());
    let has_symbol = password.chars().any(|c| !c.is_alphanumeric());

    let mut score = 0u8;
    if length >= MIN_PASSWORD_LEN {
        score += 1;
    }
    if has_lowercase && has_uppercase {
        score += 1;
    }
    if has_digit {
        score += 1;
    }
    if has_symbol {
        score += 1;
    }
    if length >= 20 {
        score = score.min(4);
    }

    let mut recommendations = Vec::new();
    if length < MIN_PASSWORD_LEN {
        recommendations.push(format!(
            "нужно минимум {MIN_PASSWORD_LEN} символов, сейчас {length}"
        ));
    }
    if !has_lowercase || !has_uppercase {
        recommendations.push("добавьте строчные и прописные буквы".to_string());
    }
    if !has_digit {
        recommendations.push("добавьте цифры".to_string());
    }
    if !has_symbol {
        recommendations.push("добавьте спецсимволы (!?@#%…)".to_string());
    }
    if length >= MIN_PASSWORD_LEN && length < 16 {
        recommendations.push("длина от 16 символов заметно надёжнее".to_string());
    }

    PasswordReport {
        length,
        min_length: MIN_PASSWORD_LEN,
        acceptable: length >= MIN_PASSWORD_LEN,
        has_lowercase,
        has_uppercase,
        has_digit,
        has_symbol,
        score: score.min(4),
        recommendations,
    }
}

/// Проверяет пароль и возвращает ошибку, если он недопустим.
pub fn ensure_acceptable(password: &str) -> Result<PasswordReport> {
    let report = check_password(password);
    if !report.acceptable {
        return Err(VaultError::WeakPassword(format!(
            "минимум {} символов",
            MIN_PASSWORD_LEN
        )));
    }
    Ok(report)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Тестовые параметры: те же, что в продакшене, но дешёвые,
    /// чтобы тесты не занимали 256 МиБ на каждый вызов.
    fn cheap_params() -> KdfParams {
        KdfParams {
            algorithm: "argon2id".to_string(),
            m_cost_kib: 64,
            t_cost: 2,
            p_cost: 1,
        }
    }

    #[test]
    fn derivation_is_deterministic() {
        let salt = [7u8; SALT_LEN];
        let a = derive_master_key("correct horse battery", &salt, &cheap_params()).unwrap();
        let b = derive_master_key("correct horse battery", &salt, &cheap_params()).unwrap();
        assert_eq!(&a[..], &b[..]);
    }

    #[test]
    fn different_password_gives_different_key() {
        let salt = [7u8; SALT_LEN];
        let a = derive_master_key("password-one-123", &salt, &cheap_params()).unwrap();
        let b = derive_master_key("password-two-123", &salt, &cheap_params()).unwrap();
        assert_ne!(&a[..], &b[..]);
    }

    #[test]
    fn different_salt_gives_different_key() {
        let a = derive_master_key("same-password-123", &[1u8; SALT_LEN], &cheap_params()).unwrap();
        let b = derive_master_key("same-password-123", &[2u8; SALT_LEN], &cheap_params()).unwrap();
        assert_ne!(&a[..], &b[..]);
    }

    #[test]
    fn short_salt_is_rejected() {
        let err = derive_master_key("password-12345", &[0u8; 4], &cheap_params());
        assert!(matches!(err, Err(VaultError::Corrupted(_))));
    }

    #[test]
    fn rejects_unknown_algorithm() {
        let params = KdfParams {
            algorithm: "scrypt".to_string(),
            ..cheap_params()
        };
        assert!(params.validate().is_err());
    }

    #[test]
    fn password_length_is_enforced() {
        assert!(!check_password("short").acceptable);
        assert!(check_password("twelve-chars").acceptable);
        assert_eq!(check_password("twelve-chars").length, 12);
    }

    #[test]
    fn password_length_counts_characters_not_bytes() {
        // 12 кириллических символов = 24 байта в UTF-8, но длина 12
        let report = check_password("пароль-двенад");
        assert_eq!(report.length, 12);
        assert!(report.acceptable);
    }

    #[test]
    fn composition_is_a_recommendation_not_a_requirement() {
        let report = check_password("aaaaaaaaaaaaaa");
        assert!(report.acceptable, "длина соблюдена — пароль допустим");
        assert!(report.has_recommendations());
        assert!(!report.has_digit);
        assert!(!report.has_symbol);
    }

    #[test]
    fn ensure_acceptable_rejects_short_password() {
        assert!(matches!(
            ensure_acceptable("short"),
            Err(VaultError::WeakPassword(_))
        ));
    }
}
