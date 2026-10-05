//! Открытый заголовок хранилища.
//!
//! Лежит в `vault/header.json` в незашифрованном виде. Секретов не содержит:
//! соль и параметры Argon2id не являются тайной, а `verifier` — это
//! шифротекст, по которому можно лишь проверить правильность пароля.

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine as _;
use serde::{Deserialize, Serialize};

use super::error::{Result, VaultError};
use super::kdf::KdfParams;

/// Сигнатура файла: отсекает попытки открыть чужим паролем не тот файл.
pub const MAGIC: &str = "FOUSBROWSER-VAULT";

/// Версия формата хранилища.
pub const FORMAT_VERSION: u32 = 1;

/// Плейнтекст, который шифруется мастер-ключом для проверки пароля.
///
/// Значение не секрет — оно нужно лишь для того, чтобы отличить верный
/// пароль от неверного.
pub const VERIFIER_PLAINTEXT: &[u8] = b"fousbrowser-vault-verifier-v1";

/// Заголовок хранилища.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VaultHeader {
    pub magic: String,
    pub format_version: u32,
    /// Идентификатор хранилища: связывает AAD всех контейнеров.
    pub vault_id: String,
    pub kdf: KdfParams,
    pub salt_b64: String,
    pub verifier_b64: String,
}

impl VaultHeader {
    pub fn new(vault_id: String, kdf: KdfParams, salt: &[u8], verifier: &[u8]) -> Self {
        Self {
            magic: MAGIC.to_string(),
            format_version: FORMAT_VERSION,
            vault_id,
            kdf,
            salt_b64: b64_encode(salt),
            verifier_b64: b64_encode(verifier),
        }
    }

    /// Проверяет сигнатуру и версию формата.
    pub fn validate(&self) -> Result<()> {
        if self.magic != MAGIC {
            return Err(VaultError::Corrupted(format!(
                "это не хранилище FousBrowser (сигнатура: {})",
                self.magic
            )));
        }
        if self.format_version > FORMAT_VERSION {
            return Err(VaultError::Corrupted(format!(
                "формат хранилища версии {} новее, чем поддерживает эта сборка ({})",
                self.format_version, FORMAT_VERSION
            )));
        }
        self.kdf.validate()?;
        Ok(())
    }

    pub fn salt(&self) -> Result<Vec<u8>> {
        b64_decode(&self.salt_b64)
    }

    pub fn verifier(&self) -> Result<Vec<u8>> {
        b64_decode(&self.verifier_b64)
    }

    /// AAD для проверочного блока.
    pub fn verifier_aad(&self) -> Vec<u8> {
        format!(
            "fousbrowser/v1/verifier/{}/{}",
            self.format_version, self.vault_id
        )
        .into_bytes()
    }

    /// AAD для контейнера метаданных.
    pub fn metadata_aad(&self) -> Vec<u8> {
        format!(
            "fousbrowser/v1/metadata/{}/{}",
            self.format_version, self.vault_id
        )
        .into_bytes()
    }

    /// AAD для данных профиля.
    pub fn profile_aad(&self, profile_id: &str) -> Vec<u8> {
        format!(
            "fousbrowser/v1/profile/{}/{}/{}",
            self.format_version, self.vault_id, profile_id
        )
        .into_bytes()
    }

    pub fn to_json(&self) -> Result<Vec<u8>> {
        Ok(serde_json::to_vec_pretty(self)?)
    }

    pub fn from_json(bytes: &[u8]) -> Result<Self> {
        let header: Self = serde_json::from_slice(bytes)?;
        header.validate()?;
        Ok(header)
    }
}

pub fn b64_encode(data: &[u8]) -> String {
    B64.encode(data)
}

pub fn b64_decode(data: &str) -> Result<Vec<u8>> {
    B64.decode(data)
        .map_err(|_| VaultError::Corrupted("некорректная base64 в заголовке".to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vault::kdf::SALT_LEN;

    fn header() -> VaultHeader {
        VaultHeader::new(
            "11111111-2222-3333-4444-555555555555".to_string(),
            KdfParams::default(),
            &[3u8; SALT_LEN],
            b"verifier-bytes",
        )
    }

    #[test]
    fn json_roundtrip_preserves_fields() {
        let original = header();
        let restored = VaultHeader::from_json(&original.to_json().unwrap()).unwrap();
        assert_eq!(restored.vault_id, original.vault_id);
        assert_eq!(restored.kdf, original.kdf);
        assert_eq!(restored.salt().unwrap(), vec![3u8; SALT_LEN]);
        assert_eq!(restored.verifier().unwrap(), b"verifier-bytes");
    }

    #[test]
    fn rejects_foreign_file() {
        let mut foreign = header();
        foreign.magic = "SOMETHING-ELSE".to_string();
        assert!(matches!(
            foreign.validate(),
            Err(VaultError::Corrupted(_))
        ));
    }

    #[test]
    fn rejects_newer_format() {
        let mut future = header();
        future.format_version = FORMAT_VERSION + 1;
        assert!(future.validate().is_err());
    }

    #[test]
    fn aad_is_bound_to_vault_and_purpose() {
        let one = header();
        let mut two = header();
        two.vault_id = "99999999-2222-3333-4444-555555555555".to_string();

        assert_ne!(one.verifier_aad(), two.verifier_aad());
        assert_ne!(one.verifier_aad(), one.metadata_aad());
        assert_ne!(one.profile_aad("a"), one.profile_aad("b"));
        assert_ne!(one.profile_aad("a"), one.metadata_aad());
    }

    #[test]
    fn invalid_base64_is_reported() {
        let mut broken = header();
        broken.salt_b64 = "не-base64!!!".to_string();
        assert!(broken.salt().is_err());
    }
}
