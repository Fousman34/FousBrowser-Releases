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
//! пользовательский каталог данных (`start/`) и открываются движком как
//! `file://`. Содержимое встроено в исполняемый файл, поэтому установка не
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

/// Знак проекта (тот же, что в интерфейсе и в значке приложения).
const LOGO: &str = include_str!("../../resources/start/logo.svg");

/// Шрифт интерфейса, чтобы страница выглядела частью лаунчера.
const FONT: &[u8] = include_bytes!("../../../static/fonts/JetBrainsMono-Variable.ttf");

/// Имя файла шрифта рядом со страницей.
const FONT_FILE: &str = "JetBrainsMono-Variable.ttf";

/// Готовит страницу в каталоге данных и возвращает путь к `index.html`.
pub fn ensure(app_root: &Path) -> Result<PathBuf> {
    let dir = app_root.join("start");
    paths::ensure_dir(&dir)?;

    write_if_changed(&dir.join("index.html"), PAGE.as_bytes())?;
    write_if_changed(&dir.join("logo.svg"), LOGO.as_bytes())?;
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
    let text = absolute.to_string_lossy().replace('\\', "/");

    let mut encoded = String::with_capacity(text.len() + 8);
    for byte in text.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' | b'/' | b':' => {
                encoded.push(byte as char)
            }
            _ => encoded.push_str(&format!("%{byte:02X}")),
        }
    }

    if encoded.starts_with('/') {
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
        // Знак на странице — тот же, что у приложения: круг и два шеврона.
        assert!(LOGO.contains("<svg"));
        assert_eq!(LOGO.matches("<circle").count(), 4);
        assert!(LOGO.contains("#22d3ee"));
        assert!(LOGO.contains("#34d399"));
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
}
