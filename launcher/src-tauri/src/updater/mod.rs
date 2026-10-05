//! Сервис обновлений движков.
//!
//! Два независимых канала: у них разные источники, разные способы проверки
//! подлинности и разные манифесты. Смешивать их нельзя.
//!
//! | Канал | Источник | Проверка |
//! |---|---|---|
//! | Normal | официальный манифест Chrome for Testing | TLS при загрузке, проверка структуры архива; контрольных сумм источник не публикует |
//! | Antidetect | GitHub Releases нашего репозитория | `SHA256SUMS` + обязательная проверка GPG-подписи встроенным публичным ключом |
//!
//! # Порядок установки
//!
//! 1. Проверка версии по манифесту канала.
//! 2. Загрузка в staging-каталог с отчётом о прогрессе.
//! 3. Проверка контрольной суммы и — для Antidetect — подписи списка сумм.
//! 4. Распаковка и атомарная подмена указателя `current.json`.
//!
//! Ни один шаг не трогает работающую версию: подмена происходит в самом
//! конце, поэтому отмена или сбой не портят текущий движок.

pub mod channel;
pub mod download;
pub mod gpg;
pub mod install;
pub mod version;

use std::path::{Path, PathBuf};

use serde::Serialize;

use crate::vault::VaultError;

/// Ошибки обновления.
#[derive(Debug, thiserror::Error)]
pub enum UpdateError {
    #[error("источник обновлений недоступен: {0}")]
    Network(String),

    #[error("источник обновлений ответил неожиданно: {0}")]
    Source(String),

    #[error("отказ по требованиям безопасности: {0}")]
    Insecure(String),

    #[error("ошибка ввода-вывода: {0}")]
    Io(#[from] std::io::Error),

    #[error("хранилище: {0}")]
    Vault(#[from] VaultError),
}

/// Результат операции обновления.
pub type UpdateResult<T> = std::result::Result<T, UpdateError>;

/// Откуда берётся обновление.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Channel {
    /// Стоковый Chromium: официальный канал.
    Normal,
    /// Наш форк с подменой отпечатка: релизы в нашем репозитории.
    Antidetect,
}

impl Channel {
    /// Имя каталога движка (`browsers/<имя>`).
    pub fn dir_name(&self) -> &'static str {
        match self {
            Channel::Normal => "normal",
            Channel::Antidetect => "antidetect",
        }
    }

    /// Человекочитаемое имя для интерфейса.
    pub fn label(&self) -> &'static str {
        match self {
            Channel::Normal => "Normal",
            Channel::Antidetect => "Antidetect",
        }
    }
}

/// Платформа, для которой ищется движок.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Platform {
    WindowsX64,
}

impl Platform {
    /// Платформа текущей сборки. `None` — сборки для этой системы не бывает.
    pub fn current() -> Option<Platform> {
        #[cfg(all(windows, target_arch = "x86_64"))]
        {
            Some(Platform::WindowsX64)
        }
        #[cfg(not(all(windows, target_arch = "x86_64")))]
        {
            None
        }
    }

    /// Имя платформы в хранилище Chrome for Testing.
    pub fn chrome_for_testing(&self) -> &'static str {
        match self {
            Platform::WindowsX64 => "win64",
        }
    }

    /// Подсказки в имени архива нашего релиза движка.
    pub fn archive_hints(&self) -> &'static [&'static str] {
        match self {
            Platform::WindowsX64 => &["win64", "windows", "win-x64", "win_x64"],
        }
    }

    /// Имя файла, под которым сохраняем архив официального движка.
    pub fn normal_archive_name(&self, version: &str) -> String {
        format!("chrome-{}-{version}.zip", self.chrome_for_testing())
    }
}

/// Найденное обновление.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Release {
    pub channel: Channel,
    pub version: String,
    /// Заметки о релизе (для Antidetect — текст из GitHub).
    pub notes: String,
    pub asset_name: String,
    pub asset_url: String,
    pub size: Option<u64>,
    /// Ожидаемая контрольная сумма, если источник её публикует.
    pub sha256: Option<String>,
    /// Где лежит список контрольных сумм (канал Antidetect).
    pub sums_url: Option<String>,
    /// Где лежит GPG-подпись списка сумм (канал Antidetect).
    pub signature_url: Option<String>,
    /// Страница релиза: её открываем человеку.
    pub page_url: String,
}

impl Release {
    /// Требует ли этот релиз обязательной проверки GPG-подписи.
    pub fn requires_signature(&self) -> bool {
        self.channel == Channel::Antidetect
    }
}

/// Куда ставится движок: `browsers/<канал>/<версия>`.
pub fn engine_dir(browsers_root: &Path, channel: Channel, version: &str) -> PathBuf {
    browsers_root.join(channel.dir_name()).join(version)
}

/// Каталог незавершённой установки: `browsers/<канал>/.staging`.
pub fn staging_dir(browsers_root: &Path, channel: Channel) -> PathBuf {
    browsers_root.join(channel.dir_name()).join(".staging")
}

/// Имя файла-указателя на текущую версию.
pub const POINTER_FILE: &str = "current.json";

/// Записывает указатель на текущую версию движка.
pub fn write_pointer(
    browsers_root: &Path,
    channel: Channel,
    version: &str,
    executable: &str,
) -> UpdateResult<()> {
    let pointer = serde_json::json!({ "version": version, "executable": executable });
    let path = browsers_root.join(channel.dir_name()).join(POINTER_FILE);
    crate::paths::write_atomic(&path, serde_json::to_vec_pretty(&pointer)?.as_slice())?;
    Ok(())
}

impl From<serde_json::Error> for UpdateError {
    fn from(error: serde_json::Error) -> Self {
        UpdateError::Source(format!("формат данных: {error}"))
    }
}

/// Владелец репозитория с релизами движка.
pub const GITHUB_OWNER: &str = "Fousman34";

/// Репозиторий, в котором лежат релизы движка и самого лаунчера.
pub const GITHUB_REPO: &str = "FousBrowser-Releases";

/// Переменная окружения для подмены адреса списка релизов.
///
/// Нужна зеркалам и проверкам: позволяет указать свой источник релизов
/// движка, не меняя сборку.
pub const RELEASES_URL_ENV: &str = "FOUSBROWSER_RELEASES_URL";

/// Адрес списка релизов GitHub.
pub fn releases_url() -> String {
    match std::env::var(RELEASES_URL_ENV) {
        Ok(value) if !value.trim().is_empty() => value.trim().to_string(),
        _ => format!(
            "https://api.github.com/repos/{GITHUB_OWNER}/{GITHUB_REPO}/releases?per_page=100"
        ),
    }
}

/// Public mirror avoids GitHub's shared-IP unauthenticated API quota.
pub const ANTIDETECT_MIRROR_URL: &str = "https://raw.githubusercontent.com/Fousman34/FousBrowser-Releases/main/browsers/antidetect/releases.json";
const EMBEDDED_RELEASES: &str = include_str!("../../../../browsers/antidetect/releases.json");

fn antidetect_source() -> UpdateResult<String> {
    // An explicitly configured source must never silently switch repositories.
    let allow_fallback = !std::env::var(RELEASES_URL_ENV).is_ok_and(|url| !url.trim().is_empty());
    antidetect_source_with(&releases_url(), allow_fallback, download::fetch_text)
}

fn antidetect_source_with(
    primary_url: &str,
    allow_fallback: bool,
    mut fetch: impl FnMut(&str) -> UpdateResult<String>,
) -> UpdateResult<String> {
    let primary = fetch(primary_url);
    if !allow_fallback {
        return primary;
    }
    match primary {
        Ok(text) => Ok(text),
        Err(error) => {
            eprintln!("GitHub API: {error}; используется резервный манифест");
            Ok(fetch(ANTIDETECT_MIRROR_URL).unwrap_or_else(|_| EMBEDDED_RELEASES.to_string()))
        }
    }
}

/// Проверяет обновление для канала целиком: запрос источника и решение.
pub fn check(channel: Channel) -> UpdateResult<Option<Release>> {
    let platform = Platform::current()
        .ok_or_else(|| UpdateError::Source("для этой системы движки не выпускаются".into()))?;
    let browsers = crate::paths::browsers_dir()?;
    let current = installed_version(&browsers, channel)?;

    match channel {
        Channel::Normal => {
            let manifest = download::fetch_text(channel::NORMAL_MANIFEST_URL)?;
            decide(channel, platform, current.as_deref(), Some(&manifest), None)
        }
        Channel::Antidetect => {
            let releases = antidetect_source()?;
            decide(channel, platform, current.as_deref(), None, Some(&releases))
        }
    }
}

/// Ставит указанную версию канала.
///
/// Версия берётся из ответа источника заново: адреса загрузки никогда не
/// приходят из интерфейса, иначе подмена ссылки в окне превращалась бы
/// в загрузку произвольного файла.
pub fn install_version(
    channel: Channel,
    version: &str,
    mut on_progress: impl FnMut(download::Progress),
    mut on_log: impl FnMut(&str),
) -> UpdateResult<PathBuf> {
    let platform = Platform::current()
        .ok_or_else(|| UpdateError::Source("для этой системы движки не выпускаются".into()))?;
    let browsers = crate::paths::browsers_dir()?;

    // Проверяем без учёта установленной версии: нужна именно запрошенная.
    let release = match channel {
        Channel::Normal => {
            let manifest = download::fetch_text(channel::NORMAL_MANIFEST_URL)?;
            channel::normal_release(&manifest, platform, None)?
        }
        Channel::Antidetect => {
            let releases = antidetect_source()?;
            channel::antidetect_release(&releases, platform, None)?
        }
    }
    .ok_or_else(|| UpdateError::Source(format!("в источнике нет версии {version}")))?;

    if release.version != version {
        return Err(UpdateError::Source(format!(
            "источник предлагает версию {}, а запрошена {version}",
            release.version
        )));
    }

    let prepared = install::prepare(&release, &browsers, platform, &mut on_progress, &mut on_log)?;
    on_log(prepared.verification_note());

    install::install(&prepared, &browsers, platform, &mut on_log)
}

/// Установленная версия движка по каналу.
pub fn current_version(channel: Channel) -> UpdateResult<Option<String>> {
    let browsers = crate::paths::browsers_dir()?;
    installed_version(&browsers, channel)
}

/// Проверяет обновления для указанного канала.
///
/// `normal_manifest` и `github_releases` — уже полученные тексты ответов:
/// сеть остаётся снаружи, поэтому разбор и решение проверяются тестами
/// без обращений к интернету.
pub fn decide(
    channel: Channel,
    platform: Platform,
    current: Option<&str>,
    normal_manifest: Option<&str>,
    github_releases: Option<&str>,
) -> UpdateResult<Option<Release>> {
    match channel {
        Channel::Normal => {
            let manifest = normal_manifest.ok_or_else(|| {
                UpdateError::Source("не передан манифест официального канала".into())
            })?;
            channel::normal_release(manifest, platform, current)
        }
        Channel::Antidetect => {
            let releases = github_releases
                .ok_or_else(|| UpdateError::Source("не передан список релизов GitHub".into()))?;
            channel::antidetect_release(releases, platform, current)
        }
    }
}

/// Установленная версия движка по указателю.
pub fn installed_version(browsers_root: &Path, channel: Channel) -> UpdateResult<Option<String>> {
    let path = browsers_root.join(channel.dir_name()).join(POINTER_FILE);
    let Ok(bytes) = std::fs::read(&path) else {
        return Ok(None);
    };
    let value: serde_json::Value = serde_json::from_slice(&bytes)?;
    Ok(value
        .get("version")
        .and_then(serde_json::Value::as_str)
        .map(str::to_string))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn api_failures_use_mirror_or_pinned_metadata_but_custom_sources_do_not() {
        let from_mirror = antidetect_source_with("primary", true, |url| {
            if url == ANTIDETECT_MIRROR_URL {
                Ok(EMBEDDED_RELEASES.into())
            } else {
                Err(UpdateError::Network("quota".into()))
            }
        })
        .unwrap();
        assert_eq!(from_mirror, EMBEDDED_RELEASES);
        let pinned = antidetect_source_with("primary", true, |_| {
            Err(UpdateError::Network("offline".into()))
        })
        .unwrap();
        assert_eq!(pinned, EMBEDDED_RELEASES);
        let mut calls = 0;
        assert!(antidetect_source_with("custom", false, |_| {
            calls += 1;
            Err(UpdateError::Network("offline".into()))
        })
        .is_err());
        assert_eq!(calls, 1);
    }

    #[test]
    fn engine_directories_are_where_the_discovery_expects_them() {
        let root = Path::new("/browsers");
        assert_eq!(
            engine_dir(root, Channel::Normal, "121.0.0.0"),
            Path::new("/browsers/normal/121.0.0.0")
        );
        assert_eq!(
            engine_dir(root, Channel::Antidetect, "1.0.0"),
            Path::new("/browsers/antidetect/1.0.0")
        );
        assert_eq!(
            staging_dir(root, Channel::Normal),
            Path::new("/browsers/normal/.staging")
        );
    }

    #[test]
    fn channel_names_match_the_engine_layout() {
        // Совпадение с engine::discovery::dir_name — не случайность:
        // обновление и запуск обязаны смотреть в один каталог.
        assert_eq!(
            Channel::Normal.dir_name(),
            crate::engine::discovery::dir_name(crate::vault::ProfileKind::Normal)
        );
        assert_eq!(
            Channel::Antidetect.dir_name(),
            crate::engine::discovery::dir_name(crate::vault::ProfileKind::Antidetect)
        );
    }

    #[test]
    fn pointer_round_trip() {
        let tmp = tempfile::tempdir().unwrap();
        assert_eq!(
            installed_version(tmp.path(), Channel::Normal).unwrap(),
            None
        );

        write_pointer(
            tmp.path(),
            Channel::Normal,
            "121.0.6167.85",
            "chrome-win64/chrome.exe",
        )
        .unwrap();
        assert_eq!(
            installed_version(tmp.path(), Channel::Normal)
                .unwrap()
                .as_deref(),
            Some("121.0.6167.85")
        );

        // Указатель совпадает по раскладке с тем, что читает discovery.
        let pointer =
            std::fs::read_to_string(tmp.path().join("normal").join(POINTER_FILE)).unwrap();
        let value: serde_json::Value = serde_json::from_str(&pointer).unwrap();
        assert_eq!(value["version"], "121.0.6167.85");
        assert_eq!(value["executable"], "chrome-win64/chrome.exe");
    }

    #[test]
    fn signature_is_required_for_antidetect_only() {
        let normal = Release {
            channel: Channel::Normal,
            version: "1".into(),
            notes: String::new(),
            asset_name: "a".into(),
            asset_url: "u".into(),
            size: None,
            sha256: None,
            sums_url: None,
            signature_url: None,
            page_url: String::new(),
        };
        let mut antidetect = normal.clone();
        antidetect.channel = Channel::Antidetect;
        assert!(!normal.requires_signature());
        assert!(antidetect.requires_signature());
    }

    #[test]
    fn decide_refuses_missing_sources() {
        assert!(matches!(
            decide(Channel::Normal, Platform::WindowsX64, None, None, None),
            Err(UpdateError::Source(_))
        ));
        assert!(matches!(
            decide(Channel::Antidetect, Platform::WindowsX64, None, None, None),
            Err(UpdateError::Source(_))
        ));
    }
}
