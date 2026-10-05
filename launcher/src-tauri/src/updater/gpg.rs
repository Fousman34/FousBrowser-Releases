//! Проверка GPG-подписи релизов движка.
//!
//! # Почему подпись обязательна
//!
//! Движок Antidetect — это исполняемый код, который лаунчер скачивает из
//! интернета и запускает от имени пользователя. Без проверки подписи
//! достаточно подменить файл в релизе, чтобы получить выполнение чужого кода
//! в профиле пользователя. Поэтому подпись — не украшение, а условие
//! установки: при несовпадении установка отвергается целиком.
//!
//! # Как это устроено
//!
//! Подписывается файл `SHA256SUMS` (список контрольных сумм всех файлов
//! релиза). Проверка идёт встроенным публичным ключом: чужой ключ не примет
//! ни одну подпись, потому что других ключей лаунчер не знает. Проверка
//! выполняется библиотекой на Rust, у пользователя не должен быть
//! установлен `gpg`.

use sequoia_openpgp as openpgp;

use openpgp::cert::Cert;
use openpgp::parse::stream::{
    DetachedVerifierBuilder, MessageLayer, MessageStructure, VerificationHelper,
};
use openpgp::parse::Parse;
use openpgp::policy::StandardPolicy;
use openpgp::Result as PgpResult;

use super::{UpdateError, UpdateResult};

/// Публичный ключ подписи релизов движка, встроенный в лаунчер.
pub const PUBLIC_KEY: &str = include_str!("../../resources/keys/fousbrowser-antidetect.asc");

/// Отпечаток встроенного ключа (для диагностики и документации).
pub const KEY_FINGERPRINT: &str = "DC34C6208E68C1257836C92365607A6A35CACE1B";

/// Проверяющий, который знает ровно один ключ — наш.
struct Helper {
    cert: Cert,
}

impl VerificationHelper for Helper {
    fn get_certs(&mut self, _ids: &[openpgp::KeyHandle]) -> PgpResult<Vec<Cert>> {
        // Возвращаем только наш ключ: подпись, сделанная любым другим, будет
        // отвергнута как «ключ не найден».
        Ok(vec![self.cert.clone()])
    }

    fn check(&mut self, structure: MessageStructure) -> PgpResult<()> {
        // Библиотека сама не отвергает неподтверждённую подпись: решение
        // принимает проверяющий. Поэтому здесь требуется, чтобы была хотя бы
        // одна подпись, подтверждённая нашим ключом. Без этой проверки
        // подделанные данные считались бы подписанными.
        for layer in structure.into_iter() {
            if let MessageLayer::SignatureGroup { results } = layer {
                if results.into_iter().any(|result| result.is_ok()) {
                    return Ok(());
                }
            }
        }

        Err(anyhow::anyhow!(
            "ни одна подпись не подтверждена встроенным публичным ключом"
        ))
    }
}

/// Проверяет отсоединённую подпись данных.
///
/// `signature` — бронированная (`-----BEGIN PGP SIGNATURE-----`) подпись,
/// `data` — подписанные байты. `public_key` нужен только тестам: в работе
/// используется встроенный ключ.
pub fn verify_detached(
    data: &[u8],
    signature: &[u8],
    public_key: Option<&str>,
) -> UpdateResult<()> {
    let armored = public_key.unwrap_or(PUBLIC_KEY);

    let cert = Cert::from_bytes(armored.as_bytes()).map_err(|error| {
        UpdateError::Insecure(format!("встроенный публичный ключ не читается: {error}"))
    })?;

    let policy = StandardPolicy::new();
    let mut verifier = DetachedVerifierBuilder::from_bytes(signature)
        .map_err(|error| UpdateError::Insecure(format!("подпись не читается: {error}")))?
        .with_policy(&policy, None, Helper { cert })
        .map_err(|error| UpdateError::Insecure(format!("подпись не принята: {error}")))?;

    verifier
        .verify_bytes(data)
        .map_err(|error| UpdateError::Insecure(format!("подпись не подтверждена: {error}")))?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const SUMS: &[u8] = include_bytes!("../../tests/fixtures/SHA256SUMS");
    const SIGNATURE: &[u8] = include_bytes!("../../tests/fixtures/SHA256SUMS.asc");
    /// Публичный ключ другого набора: на нём проверяется отказ.
    const OTHER_KEY: &str = include_str!("../../tests/fixtures/other-key.asc");

    #[test]
    fn real_signature_is_accepted() {
        verify_detached(SUMS, SIGNATURE, None)
            .expect("подпись, сделанная нашим ключом, обязана приниматься");
    }

    #[test]
    fn modified_data_is_rejected() {
        let mut tampered = SUMS.to_vec();
        // Меняем одну цифру в контрольной сумме — как это сделал бы
        // злоумышленник, подменяя файл релиза.
        let position = tampered
            .iter()
            .position(|byte| byte.is_ascii_digit())
            .expect("в списке есть цифры");
        tampered[position] = if tampered[position] == b'9' {
            b'8'
        } else {
            b'9'
        };

        let error = verify_detached(&tampered, SIGNATURE, None)
            .expect_err("изменённые данные не могут считаться подписанными");
        assert!(matches!(error, UpdateError::Insecure(_)), "{error}");
    }

    #[test]
    fn signature_from_another_key_is_rejected() {
        // Ключ из другого набора: подпись не должна приниматься,
        // потому что лаунчер знает только свой ключ.
        let error = verify_detached(SUMS, SIGNATURE, Some(OTHER_KEY))
            .expect_err("чужой ключ не должен подтверждать нашу подпись");
        assert!(matches!(error, UpdateError::Insecure(_)), "{error}");
    }

    #[test]
    fn broken_signature_is_reported() {
        let error = verify_detached(
            SUMS,
            "-----BEGIN PGP SIGNATURE-----\n\nнет\n".as_bytes(),
            None,
        )
        .expect_err("испорченная подпись обязана приводить к отказу");
        assert!(matches!(error, UpdateError::Insecure(_)), "{error}");
    }

    #[test]
    fn embedded_key_is_the_expected_one() {
        let cert = Cert::from_bytes(PUBLIC_KEY.as_bytes()).unwrap();
        let fingerprint = cert.fingerprint().to_hex().to_uppercase();
        assert_eq!(
            fingerprint, KEY_FINGERPRINT,
            "встроенный ключ должен совпадать с задокументированным отпечатком"
        );
    }

    /// Подписи всех подготовленных релизов движка обязаны проверяться **тем же
    /// кодом**, который проверяет их на машине пользователя.
    ///
    /// Тест идёт по каталогу `browsers/antidetect/*/`: если положить туда
    /// манифест с чужой или испорченной подписью, проверка не пройдёт.
    /// Внешний `gpg` для этого не нужен — ни в CI, ни у пользователя.
    #[test]
    fn every_prepared_release_has_a_valid_signature() {
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("..")
            .join("..")
            .join("browsers")
            .join("antidetect");

        let Ok(entries) = std::fs::read_dir(&root) else {
            // Каталога может не быть: это не ошибка.
            return;
        };

        let mut checked = 0;
        for entry in entries.flatten() {
            if !entry.file_type().map(|kind| kind.is_dir()).unwrap_or(false) {
                continue;
            }
            let dir = entry.path();
            let sums = dir.join("SHA256SUMS");
            let signature = dir.join("SHA256SUMS.asc");
            assert!(
                sums.is_file() && signature.is_file(),
                "в релизе {} нет списка сумм или подписи: публиковать такой релиз нельзя",
                dir.display()
            );

            let data = std::fs::read(&sums).unwrap();
            let signature_bytes = std::fs::read(&signature).unwrap();
            verify_detached(&data, &signature_bytes, None).unwrap_or_else(|error| {
                panic!(
                    "подпись релиза {} не подтверждена встроенным ключом: {error}",
                    dir.display()
                )
            });
            checked += 1;
        }

        assert!(
            checked > 0,
            "не найдено ни одного подготовленного релиза движка"
        );
    }
}
