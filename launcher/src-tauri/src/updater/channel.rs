//! Разбор источников обновлений.
//!
//! # Канал Normal: официальный манифест Chrome for Testing
//!
//! Берётся `last-known-good-versions-with-downloads.json`: в нём есть
//! `channels.Stable.version`. Ссылка на архив собирается по устойчивому
//! шаблону хранилища Chrome for Testing:
//!
//! ```text
//! https://storage.googleapis.com/chrome-for-testing-public/<версия>/<платформа>/chrome-<платформа>.zip
//! ```
//!
//! # Канал Antidetect: GitHub Releases нашего репозитория
//!
//! Берётся список релизов и выбирается последний с тегом `antidetect-v*`.
//! Обязательны три файла: архив движка, `SHA256SUMS` и `SHA256SUMS.asc`.
//! Релиз без подписи **не рассматривается вовсе**: подпись здесь не
//! украшение, а условие установки.

use serde::Deserialize;
use serde_json::Value;

use super::version;
use super::{Channel, Platform, Release, UpdateError, UpdateResult};

/// Манифест Stable-версии Chrome for Testing.
pub const NORMAL_MANIFEST_URL: &str =
    "https://googlechromelabs.github.io/chrome-for-testing/last-known-good-versions-with-downloads.json";

/// Шаблон ссылки на архив движка Normal.
pub const NORMAL_ARCHIVE_TEMPLATE: &str =
    "https://storage.googleapis.com/chrome-for-testing-public/{version}/{platform}/chrome-{platform}.zip";

/// Страница загрузок Chrome for Testing — её показываем человеку.
pub const NORMAL_PAGE_URL: &str = "https://googlechromelabs.github.io/chrome-for-testing/";

/// Префикс тега релизов движка Antidetect.
pub const ANTIDETECT_TAG_PREFIX: &str = "antidetect-v";

/// Имя списка контрольных сумм в релизе.
pub const SUMS_ASSET: &str = "SHA256SUMS";

/// Имя подписи списка сумм.
pub const SIGNATURE_ASSET: &str = "SHA256SUMS.asc";

pub fn safe_version(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value.split('.').all(|part| {
            !part.is_empty()
                && part.chars().all(|ch| ch.is_ascii_digit())
                && part.parse::<u64>().is_ok()
        })
}

pub fn safe_archive_name(value: &str) -> bool {
    !value.starts_with('.')
        && value.len() <= 255
        && value.to_ascii_lowercase().ends_with(".zip")
        && value
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || ['-', '_', '.'].contains(&ch))
}

/// Exact upstream bytes of the signed, published engine. A mirror never bypasses GPG/SHA256.
pub fn archive_mirror(release: &Release) -> Option<String> {
    let manifest: Value = serde_json::from_str(include_str!(
        "../../../../browsers/antidetect/150.0.7871.186/release.json"
    ))
    .ok()?;
    if release.channel != Channel::Antidetect
        || manifest["version"].as_str()? != release.version
        || manifest["asset_name"].as_str()? != release.asset_name
    {
        return None;
    }
    Some(manifest["upstream"]["url"].as_str()?.to_string())
}

pub fn verification_mirror(version: &str, name: &str) -> Option<String> {
    if !version.chars().all(|ch| ch.is_ascii_digit() || ch == '.')
        || version.is_empty()
        || ![SUMS_ASSET, SIGNATURE_ASSET].contains(&name)
    {
        return None;
    }
    Some(format!("https://raw.githubusercontent.com/Fousman34/FousBrowser-Releases/main/browsers/antidetect/{version}/{name}"))
}

#[derive(Debug, Deserialize)]
struct Manifest {
    channels: Channels,
}

#[derive(Debug, Deserialize)]
struct Channels {
    #[serde(rename = "Stable")]
    stable: ChannelEntry,
}

#[derive(Debug, Deserialize)]
struct ChannelEntry {
    version: String,
}

/// Разбирает манифест Stable-канала и собирает предложение обновления.
pub fn normal_release(
    manifest: &str,
    platform: Platform,
    current: Option<&str>,
) -> UpdateResult<Option<Release>> {
    let manifest: Manifest = serde_json::from_str(manifest)
        .map_err(|error| UpdateError::Source(format!("манифест не разобран: {error}")))?;

    let candidate = manifest.channels.stable.version;
    if !safe_version(&candidate) {
        return Err(UpdateError::Source(
            "манифест содержит некорректную версию движка".into(),
        ));
    }
    if !version::is_newer(&candidate, current) {
        return Ok(None);
    }

    let url = NORMAL_ARCHIVE_TEMPLATE
        .replace("{version}", &candidate)
        .replace("{platform}", platform.chrome_for_testing());

    Ok(Some(Release {
        channel: Channel::Normal,
        version: candidate.clone(),
        notes: format!("официальная сборка Chrome for Testing {candidate}"),
        asset_name: platform.normal_archive_name(&candidate),
        asset_url: url,
        size: None,
        // Официальный манифест контрольных сумм не публикует: проверяется
        // TLS при загрузке и структура архива. Это ограничение источника,
        // а не наше решение — см. docs/ARCHITECTURE.md.
        sha256: None,
        sums_url: None,
        signature_url: None,
        page_url: NORMAL_PAGE_URL.to_string(),
    }))
}

/// Разбирает список релизов GitHub и выбирает подходящий движок Antidetect.
pub fn antidetect_release(
    releases: &str,
    platform: Platform,
    current: Option<&str>,
) -> UpdateResult<Option<Release>> {
    let releases: Value = serde_json::from_str(releases)
        .map_err(|error| UpdateError::Source(format!("список релизов не разобран: {error}")))?;

    let list = releases
        .as_array()
        .ok_or_else(|| UpdateError::Source("ожидался список релизов".into()))?;

    let mut best: Option<(String, &Value)> = None;
    for release in list {
        let Some(tag) = release.get("tag_name").and_then(Value::as_str) else {
            continue;
        };
        let Some(version) = tag.strip_prefix(ANTIDETECT_TAG_PREFIX) else {
            continue;
        };
        if !safe_version(version) {
            return Err(UpdateError::Insecure(
                "некорректная версия движка в релизе".into(),
            ));
        }
        if release
            .get("draft")
            .and_then(Value::as_bool)
            .unwrap_or(false)
        {
            continue;
        }
        if !version::is_newer(version, current) {
            continue;
        }
        let newer = match &best {
            None => true,
            Some((known, _)) => version::is_newer(version, Some(known)),
        };
        if newer {
            best = Some((version.to_string(), release));
        }
    }

    let Some((version, release)) = best else {
        return Ok(None);
    };

    let assets = release
        .get("assets")
        .and_then(Value::as_array)
        .ok_or_else(|| UpdateError::Source("у релиза нет списка файлов".into()))?;

    let url_of = |name: &str| -> Option<String> {
        assets.iter().find_map(|asset| {
            let asset_name = asset.get("name").and_then(Value::as_str)?;
            if asset_name == name {
                asset
                    .get("browser_download_url")
                    .and_then(Value::as_str)
                    .map(str::to_string)
            } else {
                None
            }
        })
    };

    let Some(sums_url) = url_of(SUMS_ASSET) else {
        return Err(UpdateError::Insecure(format!(
            "в релизе antidetect-v{version} нет файла {SUMS_ASSET}: установка без проверки сумм запрещена"
        )));
    };
    let Some(signature_url) = url_of(SIGNATURE_ASSET) else {
        return Err(UpdateError::Insecure(format!(
            "в релизе antidetect-v{version} нет подписи {SIGNATURE_ASSET}: установка без GPG-проверки запрещена"
        )));
    };

    // Архив ищем по подсказкам платформы: имя может отличаться от версии к версии.
    let archive = assets.iter().find_map(|asset| {
        let name = asset.get("name").and_then(Value::as_str)?;
        if name == SUMS_ASSET || name == SIGNATURE_ASSET {
            return None;
        }
        let lowered = name.to_lowercase();
        if !safe_archive_name(name) {
            return None;
        }
        let matches = platform
            .archive_hints()
            .iter()
            .any(|hint| lowered.contains(hint));
        if !matches {
            return None;
        }
        let url = asset.get("browser_download_url").and_then(Value::as_str)?;
        let size = asset.get("size").and_then(Value::as_u64);
        Some((name.to_string(), url.to_string(), size))
    });

    let Some((asset_name, asset_url, size)) = archive else {
        return Err(UpdateError::Source(format!(
            "в релизе antidetect-v{version} нет архива для платформы {}",
            platform.chrome_for_testing()
        )));
    };

    Ok(Some(Release {
        channel: Channel::Antidetect,
        version: version.clone(),
        notes: release
            .get("body")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_string(),
        asset_name,
        asset_url,
        size,
        sha256: None,
        sums_url: Some(sums_url),
        signature_url: Some(signature_url),
        page_url: release
            .get("html_url")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_string(),
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn source_paths_and_non_archives_are_rejected() {
        for name in [
            "../antidetect-win64.zip",
            "C:\\win64.zip",
            "win64.zip:stream",
            "win64.exe",
            ".win64.zip",
        ] {
            assert!(!safe_archive_name(name), "{name}");
        }
        for v in ["../150", "150/../../1", "150..1", "", "150.0-beta"] {
            assert!(!safe_version(v), "{v}");
        }
        let releases = serde_json::to_string(&vec![github_release(
            "antidetect-v150.0.0.0",
            &[
                ("../antidetect-win64.zip", 100),
                (SUMS_ASSET, 50),
                (SIGNATURE_ASSET, 40),
            ],
        )])
        .unwrap();
        assert!(antidetect_release(&releases, Platform::WindowsX64, None).is_err());
    }

    #[test]
    fn embedded_mirror_selects_the_signed_engine_and_never_downgrades() {
        let json = include_str!("../../../../browsers/antidetect/releases.json");
        let release = antidetect_release(json, Platform::WindowsX64, None)
            .unwrap()
            .unwrap();
        assert_eq!(release.version, "150.0.7871.186");
        assert!(archive_mirror(&release)
            .unwrap()
            .starts_with("https://github.com/adryfish/fingerprint-chromium/"));
        let mut unknown = release.clone();
        unknown.version = "999.0.0.0".into();
        assert!(archive_mirror(&unknown).is_none());
        assert!(
            antidetect_release(json, Platform::WindowsX64, Some("151.0.0.0"))
                .unwrap()
                .is_none()
        );
        assert!(verification_mirror("../bad", SUMS_ASSET).is_none());
        assert!(verification_mirror("150.0.7871.186", "unknown").is_none());
    }

    const MANIFEST: &str = r#"{
        "timestamp": "2026-01-01T00:00:00.000Z",
        "channels": {
            "Stable": {"channel": "Stable", "version": "154.0.8037.92", "revision": "1"},
            "Beta": {"channel": "Beta", "version": "155.0.1.0", "revision": "2"}
        }
    }"#;

    fn github_release(tag: &str, assets: &[(&str, u64)]) -> serde_json::Value {
        serde_json::json!({
            "tag_name": tag,
            "draft": false,
            "body": "заметки",
            "html_url": format!("https://github.com/Fousman34/FousBrowser-Releases/releases/tag/{tag}"),
            "assets": assets
                .iter()
                .map(|(name, size)| serde_json::json!({
                    "name": name,
                    "size": size,
                    "browser_download_url": format!("https://example.test/{name}")
                }))
                .collect::<Vec<_>>()
        })
    }

    #[test]
    fn stable_channel_beats_the_current_version() {
        let release = normal_release(MANIFEST, Platform::WindowsX64, Some("154.0.8037.91"))
            .unwrap()
            .expect("обновление должно быть найдено");
        assert_eq!(release.version, "154.0.8037.92");
        assert_eq!(release.channel, Channel::Normal);
        assert!(
            release.asset_url.contains("/win64/chrome-win64.zip"),
            "{}",
            release.asset_url
        );
        assert!(release.asset_name.ends_with(".zip"));
        // Официальный источник сумм не публикует — это его свойство.
        assert!(release.sha256.is_none());
    }

    #[test]
    fn same_version_is_not_an_update() {
        assert!(
            normal_release(MANIFEST, Platform::WindowsX64, Some("154.0.8037.92"))
                .unwrap()
                .is_none()
        );
        assert!(
            normal_release(MANIFEST, Platform::WindowsX64, Some("200.0.0.0"))
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn broken_manifest_is_reported() {
        assert!(matches!(
            normal_release("{ это не json", Platform::WindowsX64, None),
            Err(UpdateError::Source(_))
        ));
        assert!(matches!(
            normal_release("{\"channels\":{}}", Platform::WindowsX64, None),
            Err(UpdateError::Source(_))
        ));
    }

    #[test]
    fn antidetect_release_requires_signature() {
        let without_signature = serde_json::to_string(&vec![github_release(
            "antidetect-v121.0.6167.85",
            &[("antidetect-win64.zip", 100), (SUMS_ASSET, 50)],
        )])
        .unwrap();
        let error = antidetect_release(&without_signature, Platform::WindowsX64, None).unwrap_err();
        assert!(matches!(error, UpdateError::Insecure(_)), "{error}");
        assert!(error.to_string().contains("GPG"));
    }

    #[test]
    fn antidetect_release_requires_sums() {
        let without_sums = serde_json::to_string(&vec![github_release(
            "antidetect-v121.0.6167.85",
            &[("antidetect-win64.zip", 100), (SIGNATURE_ASSET, 50)],
        )])
        .unwrap();
        assert!(matches!(
            antidetect_release(&without_sums, Platform::WindowsX64, None),
            Err(UpdateError::Insecure(_))
        ));
    }

    #[test]
    fn antidetect_release_is_selected_by_version_and_platform() {
        let releases = serde_json::to_string(&vec![
            github_release(
                "v0.1.0",
                &[("FousBrowser_0.1.0_x64-setup.exe", 10), (SUMS_ASSET, 5)],
            ),
            github_release(
                "antidetect-v120.0.0.0",
                &[
                    ("antidetect-win64.zip", 100),
                    (SUMS_ASSET, 50),
                    (SIGNATURE_ASSET, 40),
                ],
            ),
            github_release(
                "antidetect-v121.0.6167.85",
                &[
                    ("antidetect-win64.zip", 200),
                    (SUMS_ASSET, 60),
                    (SIGNATURE_ASSET, 45),
                ],
            ),
        ])
        .unwrap();

        let release = antidetect_release(&releases, Platform::WindowsX64, Some("120.0.0.0"))
            .unwrap()
            .expect("новая версия должна быть выбрана");
        assert_eq!(release.version, "121.0.6167.85");
        assert_eq!(release.channel, Channel::Antidetect);
        assert_eq!(release.size, Some(200));
        assert!(release.sums_url.is_some() && release.signature_url.is_some());

        // Релиз лаунчера не должен приниматься за движок.
        assert!(
            antidetect_release(&releases, Platform::WindowsX64, Some("121.0.6167.85"))
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn release_without_archive_for_platform_is_reported() {
        let releases = serde_json::to_string(&vec![github_release(
            "antidetect-v121.0.6167.85",
            &[
                ("antidetect-macos.zip", 100),
                (SUMS_ASSET, 50),
                (SIGNATURE_ASSET, 40),
            ],
        )])
        .unwrap();
        let error = antidetect_release(&releases, Platform::WindowsX64, None).unwrap_err();
        assert!(error.to_string().contains("архива"), "{error}");
    }
}
