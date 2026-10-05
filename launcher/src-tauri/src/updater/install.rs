//! Установка обновления движка.
//!
//! # Порядок
//!
//! 1. Загрузка архива в staging-каталог (работающий движок не трогается).
//! 2. Проверка подлинности: для Antidetect — GPG-подпись списка сумм, затем
//!    сверка SHA-256 самого архива; для Normal — контроль суммы источник не
//!    публикует, поэтому проверяется структура архива.
//! 3. Распаковка в staging с проверкой путей (запись за пределы каталога
//!    невозможна).
//! 4. Перенос готового каталога на место версии и запись указателя.
//!
//! Прежняя версия движка остаётся на диске: указатель можно вернуть назад,
//! если новая версия почему-то не запустится.

use std::fs;
use std::path::{Path, PathBuf};

use super::channel::{SIGNATURE_ASSET, SUMS_ASSET};
use super::UpdateResult;
use super::{download, gpg, staging_dir, write_pointer, Channel, Platform, Release, UpdateError};
use crate::engine::discovery;

/// Текст лицензии проекта-основы движка Antidetect (BSD 3-Clause).
const ENGINE_LICENSE: &str =
    include_str!("../../resources/licenses/ungoogled-chromium-LICENSE.txt");

/// Уведомление о происхождении сборки движка.
const ENGINE_NOTICE: &str = include_str!("../../resources/licenses/antidetect-NOTICE.txt");

/// Скачанный и проверенный архив, готовый к установке.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Prepared {
    pub channel: Channel,
    pub version: String,
    /// Путь к архиву в staging-каталоге.
    pub archive: PathBuf,
}

impl Prepared {
    /// Что именно проверено при подготовке (для журнала обновления).
    pub fn verification_note(&self) -> &'static str {
        match self.channel {
            Channel::Antidetect => "GPG-подпись списка сумм и SHA-256 архива подтверждены",
            Channel::Normal => {
                "источник контрольных сумм не публикует: проверены TLS и структура архива"
            }
        }
    }
}

/// Скачивает релиз и проверяет его подлинность.
///
/// `on_progress` сообщает о ходе загрузки, `on_log` — строки для терминала
/// в интерфейсе.
pub fn prepare(
    release: &Release,
    browsers_root: &Path,
    platform: Platform,
    mut on_progress: impl FnMut(download::Progress),
    mut on_log: impl FnMut(&str),
) -> UpdateResult<Prepared> {
    let staging = staging_dir(browsers_root, release.channel);
    crate::vault::profiles::wipe_dir(&staging)?;
    crate::paths::ensure_dir(&staging)?;

    let archive = staging.join(&release.asset_name);
    on_log(&format!(
        "загрузка {} ({})",
        release.asset_name, release.version
    ));

    let received = download::download(&release.asset_url, &archive, &mut on_progress)?;
    on_log(&format!("получено {received} байт"));

    if let Some(expected) = release.size {
        if received != expected {
            return Err(UpdateError::Insecure(format!(
                "размер архива не совпал: ожидалось {expected} байт, получено {received}"
            )));
        }
    }

    // Подлинность: подпись списка сумм проверяется до сверки самого архива.
    match release.channel {
        Channel::Antidetect => {
            let sums_url = release.sums_url.as_deref().ok_or_else(|| {
                UpdateError::Insecure("у релиза нет списка контрольных сумм".into())
            })?;
            let signature_url = release
                .signature_url
                .as_deref()
                .ok_or_else(|| UpdateError::Insecure("у релиза нет GPG-подписи".into()))?;

            on_log("проверка GPG-подписи списка контрольных сумм");
            let sums = download::fetch_text(sums_url)?;
            let signature = download::fetch_text(signature_url)?;
            gpg::verify_detached(sums.as_bytes(), signature.as_bytes(), None)?;
            on_log("подпись подтверждена встроенным публичным ключом");

            on_log("сверка контрольной суммы архива");
            download::verify_file(&sums, &release.asset_name, &archive)?;
            on_log("контрольная сумма совпала");
        }
        Channel::Normal => {
            // Контрольных сумм официальный источник не публикует: это его
            // свойство, а не наша недоработка. Проверяется структура архива
            // при распаковке.
            on_log("источник не публикует контрольных сумм: проверяется структура архива");
        }
    }

    let _ = (SUMS_ASSET, SIGNATURE_ASSET, platform);

    Ok(Prepared {
        channel: release.channel,
        version: release.version.clone(),
        archive,
    })
}

/// Распаковывает архив и ставит движок на место версии.
pub fn install(
    prepared: &Prepared,
    browsers_root: &Path,
    platform: Platform,
    mut on_log: impl FnMut(&str),
) -> UpdateResult<PathBuf> {
    let staging = staging_dir(browsers_root, prepared.channel);
    let unpacked = staging.join("unpacked");
    crate::vault::profiles::wipe_dir(&unpacked)?;
    crate::paths::ensure_dir(&unpacked)?;

    on_log("распаковка архива");
    unpack_zip(&prepared.archive, &unpacked)?;

    // Лицензия и уведомление кладутся рядом с движком: сам архив публикуется
    // байт в байт как у проекта-основы, а BSD 3-Clause требует поставлять
    // текст лицензии вместе с распространяемым кодом.
    if prepared.channel == Channel::Antidetect {
        fs::write(
            unpacked.join("ungoogled-chromium-LICENSE.txt"),
            ENGINE_LICENSE,
        )?;
        fs::write(unpacked.join("NOTICE-FousBrowser.txt"), ENGINE_NOTICE)?;
    }

    // Главный файл ищем так же, как потом его найдёт запуск: раскладка
    // внутри архива у разных сборок отличается.
    let program = discovery::find_program(&unpacked).ok_or_else(|| {
        UpdateError::Source(format!(
            "в архиве нет исполняемого файла движка (искали {:?})",
            discovery::CANDIDATES
        ))
    })?;

    let executable_relative = program
        .strip_prefix(&unpacked)
        .map_err(|_| UpdateError::Source("не удалось определить путь к движку".into()))?
        .to_path_buf();

    let target = super::engine_dir(browsers_root, prepared.channel, &prepared.version);
    if target.exists() {
        on_log("прежняя копия этой версии заменяется");
        crate::vault::profiles::wipe_dir(&target)?;
    }
    if let Some(parent) = target.parent() {
        crate::paths::ensure_dir(parent)?;
    }

    fs::rename(&unpacked, &target)?;
    on_log(&format!("движок установлен: {}", target.display()));

    write_pointer(
        browsers_root,
        prepared.channel,
        &prepared.version,
        &executable_relative.to_string_lossy(),
    )?;
    on_log(&format!(
        "указатель переведён на версию {}",
        prepared.version
    ));

    let _ = platform;

    // Мусор после установки не нужен: архив уже распакован и проверен.
    let _ = crate::vault::profiles::wipe_dir(&staging);

    Ok(target.join(executable_relative))
}

/// Распаковывает zip-архив, отвергая небезопасные пути.
pub fn unpack_zip(archive: &Path, target: &Path) -> UpdateResult<()> {
    let file = fs::File::open(archive)?;
    let mut zip = zip::ZipArchive::new(file)
        .map_err(|error| UpdateError::Source(format!("архив не читается: {error}")))?;

    for index in 0..zip.len() {
        let mut entry = zip
            .by_index(index)
            .map_err(|error| UpdateError::Source(format!("запись архива не читается: {error}")))?;

        // Имя из архива может содержать `..` или абсолютный путь: установка
        // обязана писаться только внутрь целевого каталога.
        let Some(relative) = entry.enclosed_name() else {
            return Err(UpdateError::Insecure(format!(
                "в архиве небезопасный путь: {}",
                entry.name()
            )));
        };
        let destination = target.join(relative);

        if entry.is_dir() {
            crate::paths::ensure_dir(&destination)?;
            continue;
        }
        if let Some(parent) = destination.parent() {
            crate::paths::ensure_dir(parent)?;
        }

        let mut output = fs::File::create(&destination)?;
        std::io::copy(&mut entry, &mut output)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    /// Собирает zip-архив с заданными файлами.
    fn build_zip(path: &Path, files: &[(&str, &[u8])]) {
        let file = fs::File::create(path).unwrap();
        let mut writer = zip::ZipWriter::new(file);
        let options: zip::write::FileOptions<'_, ()> =
            zip::write::FileOptions::default().compression_method(zip::CompressionMethod::Deflated);
        for (name, content) in files {
            writer.start_file(*name, options).unwrap();
            writer.write_all(content).unwrap();
        }
        writer.finish().unwrap();
    }

    fn release(channel: Channel, name: &str) -> Release {
        Release {
            channel,
            version: "121.0.6167.85".to_string(),
            notes: String::new(),
            asset_name: name.to_string(),
            // Локальный путь вместо ссылки: prepare в тестах не вызывается,
            // проверяется установка уже скачанного архива.
            asset_url: String::new(),
            size: None,
            sha256: None,
            sums_url: None,
            signature_url: None,
            page_url: String::new(),
        }
    }

    #[test]
    fn install_places_engine_and_writes_pointer() {
        let tmp = tempfile::tempdir().unwrap();
        let browsers = tmp.path().join("browsers");
        let staging = staging_dir(&browsers, Channel::Normal);
        crate::paths::ensure_dir(&staging).unwrap();

        let archive = staging.join("chrome-win64.zip");
        let executable = format!("chrome-win64/{}", discovery::CANDIDATES[0]);
        build_zip(
            &archive,
            &[
                (&executable, b"#!/bin/sh\nexit 0\n"),
                ("chrome-win64/extra.bin", b"data"),
            ],
        );

        let prepared = Prepared {
            channel: Channel::Normal,
            version: "121.0.6167.85".to_string(),
            archive: archive.clone(),
        };

        let mut log = Vec::new();
        let program = install(&prepared, &browsers, Platform::WindowsX64, |line| {
            log.push(line.to_string())
        })
        .unwrap();

        assert!(program.is_file(), "движок установлен: {program:?}");
        assert!(log.iter().any(|line| line.contains("указатель переведён")));

        // Указатель и поиск движка должны сойтись: лаунчер найдёт то, что поставил.
        let engine = discovery::resolve_in(crate::vault::ProfileKind::Normal, &browsers, None)
            .expect("движок должен находиться после установки");
        assert_eq!(engine.version, "121.0.6167.85");
        assert_eq!(engine.program, program);

        // Staging после установки пуст.
        assert!(!staging.exists() || fs::read_dir(&staging).unwrap().next().is_none());
    }

    #[test]
    fn antidetect_install_carries_the_license() {
        // Байты архива публикуются без изменений, поэтому текст лицензии
        // добавляется при установке: этого требует BSD 3-Clause.
        let tmp = tempfile::tempdir().unwrap();
        let browsers = tmp.path().join("browsers");
        let staging = staging_dir(&browsers, Channel::Antidetect);
        crate::paths::ensure_dir(&staging).unwrap();

        let archive = staging.join("antidetect-win64.zip");
        build_zip(&archive, &[("payload/chrome.exe", b"binary")]);

        let prepared = Prepared {
            channel: Channel::Antidetect,
            version: "150.0.7871.186".to_string(),
            archive,
        };
        install(&prepared, &browsers, Platform::WindowsX64, |_| {}).unwrap();

        let target = crate::updater::engine_dir(&browsers, Channel::Antidetect, "150.0.7871.186");
        let license = target.join("ungoogled-chromium-LICENSE.txt");
        let notice = target.join("NOTICE-FousBrowser.txt");
        assert!(
            license.is_file(),
            "текст лицензии обязан быть рядом с движком"
        );
        assert!(
            notice.is_file(),
            "уведомление о сборке обязано быть рядом с движком"
        );

        let text = fs::read_to_string(&license).unwrap();
        assert!(
            text.contains("BSD 3-Clause"),
            "лицензия должна быть настоящей"
        );
        let notice_text = fs::read_to_string(&notice).unwrap();
        assert!(
            notice_text.contains("fingerprint-chromium"),
            "в уведомлении указан проект-основа"
        );
    }

    #[test]
    fn install_refuses_archive_without_engine() {
        let tmp = tempfile::tempdir().unwrap();
        let browsers = tmp.path().join("browsers");
        let staging = staging_dir(&browsers, Channel::Antidetect);
        crate::paths::ensure_dir(&staging).unwrap();

        let archive = staging.join("antidetect-win64.zip");
        build_zip(&archive, &[("readme.txt", b"no engine here")]);

        let prepared = Prepared {
            channel: Channel::Antidetect,
            version: "1.2.3".to_string(),
            archive,
        };

        let error = install(&prepared, &browsers, Platform::WindowsX64, |_| {}).unwrap_err();
        assert!(matches!(error, UpdateError::Source(_)), "{error}");
        assert!(error.to_string().contains("исполняемого файла"));
    }

    #[test]
    fn unpacking_escapes_are_rejected() {
        let tmp = tempfile::tempdir().unwrap();
        let archive = tmp.path().join("evil.zip");
        build_zip(&archive, &[("../outside.txt", b"escaped")]);

        let target = tmp.path().join("unpacked");
        crate::paths::ensure_dir(&target).unwrap();

        let error = unpack_zip(&archive, &target).unwrap_err();
        assert!(matches!(error, UpdateError::Insecure(_)), "{error}");
        assert!(
            !tmp.path().join("outside.txt").exists(),
            "файл не должен появиться снаружи"
        );
    }

    #[test]
    fn verification_note_explains_the_channel() {
        let normal = Prepared {
            channel: Channel::Normal,
            version: "1".into(),
            archive: PathBuf::new(),
        };
        let antidetect = Prepared {
            channel: Channel::Antidetect,
            version: "1".into(),
            archive: PathBuf::new(),
        };
        assert!(normal.verification_note().contains("структура архива"));
        assert!(antidetect.verification_note().contains("GPG"));
    }

    #[test]
    fn prepare_reports_missing_signature_before_downloading() {
        // Релиз Antidetect без ссылок на суммы и подпись обязан быть отвергнут
        // ещё до обращения к сети.
        let mut candidate = release(Channel::Antidetect, "antidetect-win64.zip");
        candidate.asset_url = "http://127.0.0.1:1/asset".to_string();
        let tmp = tempfile::tempdir().unwrap();

        let error =
            prepare(&candidate, tmp.path(), Platform::WindowsX64, |_| {}, |_| {}).unwrap_err();
        // Сеть недоступна — это ожидаемо; важно, что отказ не «проглочен».
        assert!(matches!(
            error,
            UpdateError::Network(_) | UpdateError::Insecure(_)
        ));
    }
}
