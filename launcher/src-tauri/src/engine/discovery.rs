//! Поиск установленного движка.
//!
//! Раскладка каталогов движков не зависит от системы автора:
//!
//! ```text
//! browsers/
//!   normal/
//!     current.json          указатель: { "version": "...", "executable": "..." }
//!     <версия>/             распакованный движок
//!   antidetect/
//!     current.json
//!     <версия>/
//! ```
//!
//! Если указателя нет, берётся каталог версии с самым «старшим» именем,
//! в котором найден исполняемый файл. Имена файлов перебираются по списку
//! кандидатов: у разных сборок Chromium главный файл называется по-разному.
//!
//! Переменная окружения `FOUSBROWSER_ENGINE_PATH` подменяет движок целиком.
//! Это нужно приёмочным сценариям и переносимым сборкам; в обычной работе
//! переменная не задана.

use std::path::{Path, PathBuf};

use serde::Deserialize;

use crate::paths;
use crate::vault::metadata::ProfileKind;
use crate::vault::{Result, VaultError};

/// Переменная окружения для подмены движка.
pub const ENGINE_PATH_ENV: &str = "FOUSBROWSER_ENGINE_PATH";

/// Имя файла-указателя на текущую версию.
pub const POINTER_FILE: &str = "current.json";

/// Имена главного файла движка, которые стоит попробовать.
///
/// Первым идёт имя самого FousBrowser: собранный под проект движок
/// (Фаза B плана) носит имя проекта и его значок, а не имя чужого вендора.
#[cfg(windows)]
pub const CANDIDATES: &[&str] = &[
    "FousBrowser.exe",
    "chromium.exe",
    "chrome.exe",
    "browser.exe",
];

/// Имена главного файла движка для Unix-подобных систем.
#[cfg(not(windows))]
pub const CANDIDATES: &[&str] = &["fousbrowser", "chromium", "chrome", "browser"];

/// Найденный движок.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Engine {
    pub kind: ProfileKind,
    /// Версия для записей в журнале и интерфейсе.
    pub version: String,
    /// Исполняемый файл.
    pub program: PathBuf,
    /// Каталог версии (рабочий каталог процесса).
    pub root: PathBuf,
}

/// Имя каталога движка для типа профиля.
pub fn dir_name(kind: ProfileKind) -> &'static str {
    match kind {
        ProfileKind::Normal => "normal",
        ProfileKind::Antidetect => "antidetect",
    }
}

/// Человекочитаемое имя типа.
pub fn label(kind: ProfileKind) -> &'static str {
    match kind {
        ProfileKind::Normal => "Normal",
        ProfileKind::Antidetect => "Antidetect",
    }
}

#[derive(Debug, Deserialize)]
struct Pointer {
    version: String,
    executable: String,
}

/// Находит движок для типа профиля в стандартном каталоге.
pub fn resolve(kind: ProfileKind) -> Result<Engine> {
    resolve_in(kind, &paths::browsers_dir()?, override_path().as_deref())
}

/// Находит движок в указанном каталоге; `override_program` подменяет результат.
pub fn resolve_in(
    kind: ProfileKind,
    browsers_root: &Path,
    override_program: Option<&Path>,
) -> Result<Engine> {
    if let Some(program) = override_program {
        if !program.is_file() {
            return Err(VaultError::EngineMissing(format!(
                "движок из {ENGINE_PATH_ENV} не найден: {}",
                program.display()
            )));
        }
        let root = program
            .parent()
            .map(Path::to_path_buf)
            .unwrap_or_else(|| browsers_root.to_path_buf());
        return Ok(Engine {
            kind,
            version: "override".to_string(),
            program: program.to_path_buf(),
            root,
        });
    }

    let root = browsers_root.join(dir_name(kind));

    if let Some(engine) = from_pointer(kind, &root)? {
        return Ok(engine);
    }
    if let Some(engine) = from_newest_version(kind, &root)? {
        return Ok(engine);
    }

    Err(VaultError::EngineMissing(format!(
        "движок {} не установлен: каталог {} пуст",
        label(kind),
        root.display()
    )))
}

/// Движок из указателя `current.json`.
fn from_pointer(kind: ProfileKind, root: &Path) -> Result<Option<Engine>> {
    let path = root.join(POINTER_FILE);
    let bytes = match std::fs::read(&path) {
        Ok(bytes) => bytes,
        Err(_) => return Ok(None),
    };
    let pointer: Pointer = match serde_json::from_slice(&bytes) {
        Ok(pointer) => pointer,
        // Повреждённый указатель — не повод падать: ниже есть перебор версий.
        Err(_) => return Ok(None),
    };
    let version_root = root.join(&pointer.version);
    let program = version_root.join(&pointer.executable);
    if !program.is_file() {
        return Ok(None);
    }
    Ok(Some(Engine {
        kind,
        version: pointer.version,
        program,
        root: version_root,
    }))
}

/// Движок из самого «старшего» каталога версии.
fn from_newest_version(kind: ProfileKind, root: &Path) -> Result<Option<Engine>> {
    let entries = match std::fs::read_dir(root) {
        Ok(entries) => entries,
        Err(_) => return Ok(None),
    };

    let mut versions: Vec<PathBuf> = Vec::new();
    for entry in entries {
        let entry = entry?;
        if entry.file_type()?.is_dir() {
            versions.push(entry.path());
        }
    }
    // Имена версий сравниваются как строки: для «1.10» против «1.9» это даст
    // неверный порядок, но выбор версии всё равно делает указатель, а перебор
    // нужен лишь как запасной путь.
    versions.sort_by(|left, right| right.file_name().cmp(&left.file_name()));

    for version_root in versions {
        if let Some(program) = find_program(&version_root) {
            let version = version_root
                .file_name()
                .map(|name| name.to_string_lossy().to_string())
                .unwrap_or_else(|| "неизвестно".to_string());
            return Ok(Some(Engine {
                kind,
                version,
                program,
                root: version_root,
            }));
        }
    }
    Ok(None)
}

/// Ищет главный файл движка в каталоге и на один уровень глубже.
fn find_program(root: &Path) -> Option<PathBuf> {
    for name in CANDIDATES {
        let candidate = root.join(name);
        if candidate.is_file() {
            return Some(candidate);
        }
    }
    let entries = std::fs::read_dir(root).ok()?;
    for entry in entries.flatten() {
        let path = entry.path();
        if !path.is_dir() {
            continue;
        }
        for name in CANDIDATES {
            let candidate = path.join(name);
            if candidate.is_file() {
                return Some(candidate);
            }
        }
    }
    None
}

/// Программа из переменной окружения, если она задана.
pub fn override_path() -> Option<PathBuf> {
    std::env::var(ENGINE_PATH_ENV)
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
        .map(PathBuf::from)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn write_program(dir: &Path, name: &str) {
        fs::create_dir_all(dir).unwrap();
        fs::write(dir.join(name), b"#!/bin/sh\nexit 0\n").unwrap();
    }

    #[test]
    fn pointer_wins_over_directory_scan() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().join("normal");
        write_program(&root.join("100.0.0"), CANDIDATES[0]);
        write_program(&root.join("200.0.0"), CANDIDATES[0]);
        fs::write(
            root.join(POINTER_FILE),
            format!(
                "{{\"version\":\"100.0.0\",\"executable\":\"{}\"}}",
                CANDIDATES[0]
            ),
        )
        .unwrap();

        let engine = resolve_in(ProfileKind::Normal, tmp.path(), None).unwrap();
        assert_eq!(engine.version, "100.0.0");
        assert!(engine.program.ends_with(CANDIDATES[0]));
    }

    #[test]
    fn broken_pointer_falls_back_to_directory_scan() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().join("normal");
        write_program(&root.join("150.0.0"), CANDIDATES[0]);
        fs::write(root.join(POINTER_FILE), b"{ broken").unwrap();

        let engine = resolve_in(ProfileKind::Normal, tmp.path(), None).unwrap();
        assert_eq!(engine.version, "150.0.0");
    }

    #[test]
    fn nested_layout_is_found() {
        // Chrome for Testing распаковывается как chrome-win64/chrome.exe
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().join("antidetect");
        write_program(&root.join("121.0.0").join("chrome-win64"), CANDIDATES[0]);

        let engine = resolve_in(ProfileKind::Antidetect, tmp.path(), None).unwrap();
        assert_eq!(engine.version, "121.0.0");
        assert_eq!(dir_name(engine.kind), "antidetect");
    }

    #[test]
    fn missing_engine_reports_the_directory() {
        let tmp = tempfile::tempdir().unwrap();
        let error = resolve_in(ProfileKind::Normal, tmp.path(), None).unwrap_err();
        assert!(matches!(error, VaultError::EngineMissing(_)));
        assert!(error.to_string().contains("Normal"));
    }

    #[test]
    fn override_program_is_used_when_present() {
        let tmp = tempfile::tempdir().unwrap();
        let program = tmp.path().join("my-chromium.exe");
        fs::write(&program, b"x").unwrap();

        let engine = resolve_in(ProfileKind::Antidetect, tmp.path(), Some(&program)).unwrap();
        assert_eq!(engine.version, "override");
        assert_eq!(engine.program, program);
    }

    #[test]
    fn override_program_must_exist() {
        let tmp = tempfile::tempdir().unwrap();
        let missing = tmp.path().join("nope.exe");
        assert!(matches!(
            resolve_in(ProfileKind::Normal, tmp.path(), Some(&missing)),
            Err(VaultError::EngineMissing(_))
        ));
    }
}
