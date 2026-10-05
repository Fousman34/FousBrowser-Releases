//! Определение исполняемого файла процесса по его идентификатору.
//!
//! Нужно для двух задач:
//!
//! - оформление окна профиля читает из ресурсов движка его настоящее
//!   название;
//! - восстановление после краха проверяет, что процесс с записанным в журнале
//!   идентификатором — действительно тот движок, который лаунчер запускал,
//!   а не посторонний процесс, получивший тот же номер после перезапуска.
//!
//! Вторая проверка принципиальна: завершать чужой процесс по одному лишь
//! номеру нельзя.

use std::path::PathBuf;

/// Путь к исполняемому файлу процесса.
pub fn executable_of(pid: u32) -> Option<PathBuf> {
    #[cfg(windows)]
    {
        windows_executable(pid)
    }
    #[cfg(not(windows))]
    {
        // В Linux сведения о процессе лежат в /proc.
        std::fs::read_link(format!("/proc/{pid}/exe")).ok()
    }
}

/// Windows: `QueryFullProcessImageNameW` даёт полный путь процесса.
#[cfg(windows)]
fn windows_executable(pid: u32) -> Option<PathBuf> {
    use std::ffi::c_void;

    const PROCESS_QUERY_LIMITED_INFORMATION: u32 = 0x1000;

    #[link(name = "kernel32")]
    extern "system" {
        fn OpenProcess(access: u32, inherit: i32, pid: u32) -> *mut c_void;
        fn QueryFullProcessImageNameW(
            process: *mut c_void,
            flags: u32,
            buffer: *mut u16,
            size: *mut u32,
        ) -> i32;
        fn CloseHandle(handle: *mut c_void) -> i32;
    }

    let handle = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid) };
    if handle.is_null() {
        return None;
    }

    let mut buffer = vec![0u16; 1024];
    let mut size = buffer.len() as u32;
    let ok = unsafe { QueryFullProcessImageNameW(handle, 0, buffer.as_mut_ptr(), &mut size) };
    unsafe { CloseHandle(handle) };
    if ok == 0 {
        return None;
    }
    buffer.truncate(size as usize);
    Some(PathBuf::from(String::from_utf16_lossy(&buffer)))
}

/// Живёт ли процесс с таким идентификатором.
pub fn is_alive(pid: u32) -> bool {
    if pid == 0 {
        return false;
    }
    executable_of(pid).is_some()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn current_process_has_an_executable() {
        let pid = std::process::id();
        let path = executable_of(pid);
        assert!(path.is_some(), "у текущего процесса обязан быть путь");
        let path = path.unwrap();
        assert!(path.is_absolute(), "путь должен быть абсолютным: {path:?}");
    }

    #[test]
    fn is_alive_matches_reality() {
        assert!(is_alive(std::process::id()));
        // Номера процессов такого размера не выдаются.
        assert!(!is_alive(0));
        assert!(!is_alive(4_000_000_000));
    }
}
