//! Стартовая страница профиля.
//!
//! Движок открывает не свою страницу новой вкладки, а нашу: знак проекта и
//! одна строка поиска. Так на экране нет чужого оформления и чужих значков —
//! поиск уходит в Google, но выглядит это как FousBrowser.
//!
//! # Почему файлы записываются, а не отдаются по сети
//!
//! Лаунчер не поднимает ради страницы веб-сервер: страница статична, а
//! лишний слушающий сокет — лишняя поверхность атаки. Файлы кладутся в
//! пользовательский каталог данных (`start/`) и загружаются как расширение
//! Manifest V3 с chrome_url_overrides.newtab, без разрешений на сайты.
//! Содержимое встроено в исполняемый файл, поэтому установка не
//! зависит от того, что лежит рядом с ним.
//!
//! Запись идемпотентна: файл перезаписывается только если содержимое
//! отличается. Это важно, потому что шрифт весит около 300 КиБ.

use std::fs;
use std::path::{Path, PathBuf};

use crate::paths;
use crate::vault::Result;

/// Разметка страницы.
const PAGE: &str = include_str!("../../resources/start/index.html");
const SCRIPT: &str = include_str!("../../resources/start/page.js");
const MANIFEST: &str = include_str!("../../resources/start/manifest.json");

/// Знак проекта (тот же, что в интерфейсе и в значке приложения).
const LOGO: &str = include_str!("../../resources/start/logo.svg");

/// Шрифт интерфейса, чтобы страница выглядела частью лаунчера.
const FONT: &[u8] = include_bytes!("../../../static/fonts/JetBrainsMono-Variable.ttf");

/// Имя файла шрифта рядом со страницей.
const FONT_FILE: &str = "JetBrainsMono-Variable.ttf";

pub fn has_saved_session(profile_root: &Path) -> bool {
    let default = profile_root.join("Default");
    let sessions = fs::read_dir(default.join("Sessions"));
    if let Ok(entries) = sessions {
        if entries.flatten().any(|entry| {
            entry.file_name().to_string_lossy().starts_with("Session_")
                && entry
                    .metadata()
                    .is_ok_and(|meta| meta.is_file() && meta.len() > 0)
        }) {
            return true;
        }
    }
    ["Last Session", "Current Session"].iter().any(|name| {
        fs::metadata(default.join(name)).is_ok_and(|meta| meta.is_file() && meta.len() > 0)
    })
}

/// Готовит страницу в каталоге данных и возвращает путь к `index.html`.
pub fn ensure(app_root: &Path) -> Result<PathBuf> {
    let dir = app_root.join("start");
    paths::ensure_dir(&dir)?;

    write_if_changed(&dir.join("index.html"), PAGE.as_bytes())?;
    write_if_changed(&dir.join("logo.svg"), LOGO.as_bytes())?;
    write_if_changed(&dir.join("page.js"), SCRIPT.as_bytes())?;
    write_if_changed(&dir.join("manifest.json"), MANIFEST.as_bytes())?;
    write_if_changed(
        &dir.join("icon.png"),
        include_bytes!("../../icons/128x128.png"),
    )?;
    write_if_changed(&dir.join(FONT_FILE), FONT)?;

    Ok(dir.join("index.html"))
}

/// Записывает файл, только если его содержимое отличается.
///
/// Возвращает `true`, если файл был записан.
pub fn write_if_changed(path: &Path, content: &[u8]) -> Result<bool> {
    if let Ok(existing) = fs::read(path) {
        if existing == content {
            return Ok(false);
        }
    }
    paths::write_atomic(path, content)?;
    Ok(true)
}

/// Преобразует путь в URL вида `file:///...`.
///
/// Windows: `D:\Папка\index.html` → `file:///D:/%D0%9F%D0%B0%D0%BF%D0%BA%D0%B0/index.html`.
/// Кодируется всё, кроме безопасных символов: иначе пробелы и кириллица
/// в пути ломали бы открытие страницы.
pub fn file_url(path: &Path) -> String {
    let absolute = path.canonicalize().unwrap_or_else(|_| path.to_path_buf());
    let normalized = absolute.to_string_lossy().replace('\\', "/");
    // canonicalize() returns Windows extended-length paths, which are not URLs.
    let text = if let Some(unc) = normalized.strip_prefix("//?/UNC/") {
        format!("//{unc}")
    } else {
        normalized
            .strip_prefix("//?/")
            .unwrap_or(&normalized)
            .to_string()
    };

    let mut encoded = String::with_capacity(text.len() + 8);
    for byte in text.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' | b'/' | b':' => {
                encoded.push(byte as char)
            }
            _ => encoded.push_str(&format!("%{byte:02X}")),
        }
    }

    if encoded.starts_with("//") {
        format!("file:{encoded}")
    } else if encoded.starts_with('/') {
        format!("file://{encoded}")
    } else {
        // Путь без ведущей косой черты (Windows-диск) — три косые черты.
        format!("file:///{encoded}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn newtab_extension_has_no_site_or_browser_permissions() {
        let manifest: serde_json::Value = serde_json::from_str(MANIFEST).unwrap();
        assert_eq!(manifest["manifest_version"], 3);
        assert_eq!(manifest["chrome_url_overrides"]["newtab"], "index.html");
        assert!(manifest.get("permissions").is_none());
        assert!(manifest.get("host_permissions").is_none());
        assert!(manifest["key"].as_str().unwrap().len() > 100);
        let tmp = tempfile::tempdir().unwrap();
        ensure(tmp.path()).unwrap();
        for file in ["manifest.json", "page.js", "icon.png"] {
            assert!(tmp.path().join("start").join(file).is_file());
        }
    }

    #[test]
    fn page_is_prepared_once_and_reused() {
        let tmp = tempfile::tempdir().unwrap();
        let path = ensure(tmp.path()).unwrap();
        assert!(path.is_file());
        assert!(tmp.path().join("start").join("logo.svg").is_file());
        assert!(tmp.path().join("start").join(FONT_FILE).is_file());

        // Второй вызов не перезаписывает файлы: содержимое уже верное.
        assert!(!write_if_changed(&path, PAGE.as_bytes()).unwrap());
        assert!(write_if_changed(&path, b"<html></html>").unwrap());
        assert!(write_if_changed(&path, PAGE.as_bytes()).unwrap());
    }

    #[test]
    fn page_has_exactly_one_search_line_to_google() {
        assert!(PAGE.contains("https://www.google.com/search"));
        assert_eq!(
            PAGE.matches("<input").count(),
            1,
            "на странице ровно одно поле"
        );
        assert_eq!(PAGE.matches("<form").count(), 1);
        // Чужого оформления на странице нет.
        let lowered = PAGE.to_lowercase();
        for vendor in ["edge", "yandex", "opera", "chrome"] {
            assert!(
                !lowered.contains(vendor),
                "на стартовой странице не должно быть чужого имени: {vendor}"
            );
        }
    }

    #[test]
    fn logo_matches_the_application_icon_geometry() {
        // Shared vector master: dark orbit, violet F and coral accent.
        assert!(LOGO.contains("<svg"));
        assert!(LOGO.contains("<polygon"));
        assert!(LOGO.contains("#b79aff"));
        assert!(LOGO.contains("#ff927c"));
    }

    #[test]
    fn file_url_encodes_spaces_and_keeps_the_drive() {
        let url = file_url(Path::new("/tmp/папка с пробелом/index.html"));
        assert!(url.starts_with("file:///"), "url: {url}");
        assert!(url.contains("%20"), "пробел обязан кодироваться: {url}");
        assert!(
            !url.contains('\\'),
            "в URL не должно быть обратных слэшей: {url}"
        );

        #[cfg(windows)]
        {
            let url = file_url(Path::new(
                r"C:\Users\user\AppData\Roaming\FousBrowser\start\index.html",
            ));
            assert!(url.starts_with("file:///C:/"), "url: {url}");
        }
    }

    #[test]
    fn existing_windows_file_has_valid_url() {
        let tmp = tempfile::tempdir().unwrap();
        let page = ensure(tmp.path()).unwrap();
        let url = file_url(&page);
        assert!(!url.contains("%3F"), "extended path prefix leaked: {url}");
        assert!(url.starts_with("file:///"), "{url}");
        assert!(!url.starts_with("file:////"), "{url}");
    }
}
