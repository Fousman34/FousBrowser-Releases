//! Симметричное шифрование и вывод подключей.
//!
//! - Данные: XChaCha20-Poly1305 (24-байтовый nonce, 16-байтовый тег).
//! - Подключи: HKDF-SHA256 от мастер-ключа, отдельный на каждое назначение.
//! - Формат контейнера: `nonce || ciphertext || tag`.
//! - AAD всегда включает назначение, версию формата и идентификатор
//!   хранилища (или профиля) — это не даёт перенести шифротекст в другой
//!   контейнер или подменить его чужим.

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use hkdf::Hkdf;
use sha2::Sha256;
use zeroize::Zeroizing;

use super::error::{Result, VaultError};
use super::kdf::KEY_LEN;

/// Длина XChaCha20 nonce.
pub const NONCE_LEN: usize = 24;

/// Длина тега Poly1305.
pub const TAG_LEN: usize = 16;

/// Случайные байты от генератора ОС.
pub fn random_bytes<const N: usize>() -> Result<[u8; N]> {
    let mut buffer = [0u8; N];
    getrandom::fill(&mut buffer)
        .map_err(|_| VaultError::Crypto("генератор случайных чисел ОС недоступен"))?;
    Ok(buffer)
}

/// Случайный вектор заданной длины.
pub fn random_vec(len: usize) -> Result<Vec<u8>> {
    let mut buffer = vec![0u8; len];
    getrandom::fill(&mut buffer)
        .map_err(|_| VaultError::Crypto("генератор случайных чисел ОС недоступен"))?;
    Ok(buffer)
}

/// Выводит подключ из мастер-ключа.
///
/// `salt` привязывает подключ к хранилищу, `info` — к назначению.
pub fn derive_subkey(
    master: &[u8; KEY_LEN],
    salt: &[u8],
    info: &[u8],
) -> Result<Zeroizing<[u8; KEY_LEN]>> {
    let hkdf = Hkdf::<Sha256>::new(Some(salt), master);
    let mut out = Zeroizing::new([0u8; KEY_LEN]);
    hkdf.expand(info, &mut out[..])
        .map_err(|_| VaultError::Crypto("HKDF: запрошен слишком длинный выход"))?;
    Ok(out)
}

/// Шифрует данные. Возвращает `nonce || ciphertext`.
pub fn seal(key: &[u8; KEY_LEN], aad: &[u8], plaintext: &[u8]) -> Result<Vec<u8>> {
    let cipher = XChaCha20Poly1305::new_from_slice(key)
        .map_err(|_| VaultError::Crypto("некорректная длина ключа"))?;
    let nonce_bytes = random_bytes::<NONCE_LEN>()?;
    let nonce = XNonce::try_from(&nonce_bytes[..])
        .map_err(|_| VaultError::Crypto("некорректная длина nonce"))?;
    let ciphertext = cipher
        .encrypt(
            &nonce,
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .map_err(|_| VaultError::Crypto("ошибка шифрования"))?;

    let mut out = Vec::with_capacity(NONCE_LEN + ciphertext.len());
    out.extend_from_slice(&nonce_bytes);
    out.extend_from_slice(&ciphertext);
    Ok(out)
}

/// Расшифровывает контейнер `nonce || ciphertext`.
///
/// Любое несоответствие ключа, AAD или повреждение байтов даёт ошибку —
/// открытого текста в этом случае не возвращается.
pub fn open(key: &[u8; KEY_LEN], aad: &[u8], sealed: &[u8]) -> Result<Vec<u8>> {
    if sealed.len() < NONCE_LEN + TAG_LEN {
        return Err(VaultError::Corrupted(
            "контейнер короче минимально возможного".to_string(),
        ));
    }
    let (nonce_bytes, ciphertext) = sealed.split_at(NONCE_LEN);
    let nonce = XNonce::try_from(nonce_bytes)
        .map_err(|_| VaultError::Corrupted("некорректная длина nonce".to_string()))?;
    let cipher = XChaCha20Poly1305::new_from_slice(key)
        .map_err(|_| VaultError::Crypto("некорректная длина ключа"))?;
    cipher
        .decrypt(
            &nonce,
            Payload {
                msg: ciphertext,
                aad,
            },
        )
        .map_err(|_| VaultError::Crypto("проверка подлинности не пройдена"))
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY: [u8; KEY_LEN] = [42u8; KEY_LEN];

    #[test]
    fn seal_open_roundtrip() {
        let aad = b"fousbrowser/v1/test";
        let sealed = seal(&KEY, aad, b"secret payload").unwrap();
        assert_ne!(&sealed[..], b"secret payload");
        let opened = open(&KEY, aad, &sealed).unwrap();
        assert_eq!(opened, b"secret payload");
    }

    #[test]
    fn nonce_differs_between_messages() {
        let aad = b"aad";
        let first = seal(&KEY, aad, b"same").unwrap();
        let second = seal(&KEY, aad, b"same").unwrap();
        assert_ne!(
            first[..NONCE_LEN],
            second[..NONCE_LEN],
            "nonce обязан быть уникальным"
        );
        assert_ne!(first, second);
    }

    #[test]
    fn wrong_key_fails() {
        let aad = b"aad";
        let sealed = seal(&KEY, aad, b"payload").unwrap();
        let other = [43u8; KEY_LEN];
        assert!(open(&other, aad, &sealed).is_err());
    }

    #[test]
    fn wrong_aad_fails() {
        let sealed = seal(&KEY, b"aad-one", b"payload").unwrap();
        assert!(
            open(&KEY, b"aad-two", &sealed).is_err(),
            "AAD должен связывать контейнер с назначением"
        );
    }

    #[test]
    fn tampering_is_detected() {
        let aad = b"aad";
        let mut sealed = seal(&KEY, aad, b"payload").unwrap();
        let last = sealed.len() - 1;
        sealed[last] ^= 0x01;
        assert!(open(&KEY, aad, &sealed).is_err());
    }

    #[test]
    fn truncated_container_is_rejected() {
        assert!(matches!(
            open(&KEY, b"aad", &[0u8; NONCE_LEN]),
            Err(VaultError::Corrupted(_))
        ));
    }

    #[test]
    fn subkeys_are_domain_separated() {
        let master = [9u8; KEY_LEN];
        let salt = b"vault-salt";
        let metadata = derive_subkey(&master, salt, b"metadata").unwrap();
        let profile = derive_subkey(&master, salt, b"profile").unwrap();
        assert_ne!(&metadata[..], &profile[..]);

        let other = derive_subkey(&master, b"other-salt", b"metadata").unwrap();
        assert_ne!(&metadata[..], &other[..]);
    }
}
