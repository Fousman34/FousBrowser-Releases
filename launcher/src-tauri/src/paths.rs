//! Определение пользовательских каталогов.
//!
//! ВАЖНО: данные пользователя НИКОГДА не пишутся в каталог установки.
//!
//! | ОС      | Каталог данных                        | Каталог настроек          |
//! |---------|---------------------------------------|---------------------------|
//! | Windows | `%APPDATA%\FousBrowser`               | тот же                    |
//! | Linux   | `~/.local/share/FousBrowser`          | `~/.config/FousBrowser`   |
//!
//! Переменная окружения `FOUSBROWSER_HOME` переопределяет каталог данных
//! целиком — используется тестами и портативным режимом.

use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use directories::BaseDirs;

/// Имя каталога приложения в пользовательской директории.
pub const APP_DIR_NAME: &str = "FousBrowser";

/// Переменная окружения для переопределения каталога данных.
pub const HOME_ENV: &str = "FOUSBROWSER_HOME";

/// Корневой каталог данных приложения.
pub fn app_root() -> io::Result<PathBuf> {
    if let Some(custom) = override_root() {
        return Ok(custom);
    }
    let base = BaseDirs::new().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::NotFound,
            "не удалось определить пользовательские каталоги",
        )
    })?;
    Ok(base.data_dir().join(APP_DIR_NAME))
}

/// Каталог настроек (на Windows совпадает с каталогом данных).
pub fn config_root() -> io::Result<PathBuf> {
    if let Some(custom) = override_root() {
        return Ok(custom);
    }
    #[cfg(target_os = "linux")]
    {
        let base = BaseDirs::new().ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::NotFound,
                "не удалось определить пользовательские каталоги",
            )
        })?;
        Ok(base.config_dir().join(APP_DIR_NAME))
    }
    #[cfg(not(target_os = "linux"))]
    {
        app_root()
    }
}

/// Каталог хранилища (зашифрованные метаданные, профили, счётчик попыток).
pub fn vault_dir() -> io::Result<PathBuf> {
    Ok(app_root()?.join("vault"))
}

/// Каталог зашифрованных профилей.
pub fn profiles_dir() -> io::Result<PathBuf> {
    Ok(vault_dir()?.join("profiles"))
}

/// Каталог временных расшифрованных копий профилей.
pub fn temp_dir() -> io::Result<PathBuf> {
    Ok(vault_dir()?.join("tmp"))
}

/// Каталог скачанных браузерных движков.
pub fn browsers_dir() -> io::Result<PathBuf> {
    Ok(app_root()?.join("browsers"))
}

fn override_root() -> Option<PathBuf> {
    match std::env::var(HOME_ENV) {
        Ok(value) if !value.trim().is_empty() => Some(PathBuf::from(value)),
        _ => None,
    }
}

/// Создаёт каталог, если его нет, с правами `0700` на Unix.
pub fn ensure_dir(path: &Path) -> io::Result<()> {
    if path.is_dir() {
        return Ok(());
    }
    fs::create_dir_all(path)?;
    restrict_permissions(path)
}

/// Снимает права группы и остальных на Unix. На Windows каталоги в профиле
/// пользователя уже ограничены ACL, поэтому вызов ничего не делает.
pub fn restrict_permissions(path: &Path) -> io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = if path.is_dir() { 0o700 } else { 0o600 };
        let mut perms = fs::metadata(path)?.permissions();
        perms.set_mode(mode);
        fs::set_permissions(path, perms)?;
    }
    #[cfg(not(unix))]
    {
        let _ = path;
    }
    Ok(())
}

/// Атомарная запись: временный файл → `fsync` → переименование.
///
/// Гарантирует, что при падении процесса на диске не останется обрезанный
/// файл: либо старое содержимое, либо новое целиком.
pub fn write_atomic(path: &Path, data: &[u8]) -> io::Result<()> {
    use std::io::Write;

    if let Some(parent) = path.parent() {
        ensure_dir(parent)?;
    }
    let tmp = tmp_path_for(path);
    {
        let mut file = fs::File::create(&tmp)?;
        file.write_all(data)?;
        file.sync_all()?;
    }
    restrict_permissions(&tmp)?;
    fs::rename(&tmp, path)?;
    Ok(())
}

fn tmp_path_for(path: &Path) -> PathBuf {
    let mut name = path.file_name().unwrap_or_default().to_os_string();
    name.push(".tmp");
    path.with_file_name(name)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn write_atomic_replaces_content() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("nested").join("data.json");

        write_atomic(&file, b"first").unwrap();
        assert_eq!(fs::read(&file).unwrap(), b"first");

        write_atomic(&file, b"second").unwrap();
        assert_eq!(fs::read(&file).unwrap(), b"second");

        // временный файл не должен оставаться
        assert!(!dir.path().join("nested").join("data.json.tmp").exists());
    }

    #[test]
    fn override_env_wins() {
        let dir = tempfile::tempdir().unwrap();
        // переменная читается через override_root, проверяем сам механизм
        std::env::set_var(HOME_ENV, dir.path());
        assert_eq!(app_root().unwrap(), dir.path());
        std::env::remove_var(HOME_ENV);
    }
}
