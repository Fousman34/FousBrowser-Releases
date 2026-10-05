//! Оформление окна запущенного профиля и слежение за ним.
//!
//! Окно принадлежит процессу движка, поэтому лаунчер приводит его к виду
//! проекта: заголовок «… — FousBrowser» и **наш** значок. Без этого в списке
//! окон и на панели задач был бы виден чужой браузер с чужим названием.
//!
//! # Как это сделано
//!
//! На Windows окну отправляются сообщения Win32: `SetWindowTextW` задаёт
//! заголовок, `SendMessageW(WM_SETICON)` — значок большого и малого размера.
//! Значок извлекается из исполняемого файла самого лаунчера (`ExtractIconW`),
//! то есть это ровно значок проекта, а не копия чужого. Дескрипторы значков —
//! объекты уровня сессии, поэтому передача их чужому процессу допустима.
//!
//! Оформление поддерживается постоянно: движок возвращает свой заголовок
//! после загрузки страниц, поэтому имя вендора вырезается из заголовка
//! повторно (см. [`retitle`]), а значок возвращается на место.
//!
//! # Почему закрытие окна делается сообщением, а не `taskkill`
//!
//! `taskkill` без `/F` окно не закрывает: движок на такой «сигнал» не
//! реагирует (проверено). Поэтому вежливая остановка — это `WM_CLOSE` окну,
//! то есть ровно то же, что нажатие крестика пользователем.
//!
//! Поддерживается только Windows: сборки для macOS и Linux не выпускаются,
//! поэтому оформление делается единственным доступным способом.

use std::sync::atomic::AtomicIsize;
use std::sync::Arc;
use std::time::Duration;

/// Как часто проверять оформление и жизнь окна.
const POLL: Duration = Duration::from_millis(400);

/// Вежливое закрытие окна профиля (то же, что нажатие крестика).
pub use windows::close_window;

/// Сколько попыток дождаться появления окна (примерно 30 секунд).
const APPEAR_TRIES: usize = 75;

/// Запускает слежение за окном профиля.
///
/// `handle` получает описатель окна (0 — окно ещё не найдено или уже
/// закрылось); им пользуется остановка профиля.
pub fn start(pid: u32, profile_name: String, engine_stem: String, handle: Arc<AtomicIsize>) {
    std::thread::spawn(move || {
        windows::manage(pid, &profile_name, &engine_stem, &handle);
    });
}

/// Разделители, которыми движок отделяет название продукта от заголовка
/// страницы: «Страница - Продукт», «Страница — Продукт».
const TITLE_SEPARATORS: [&str; 3] = [" - ", " — ", " – "];

/// Возвращает заголовок без чужого имени, но с нашим.
///
/// `brand_names` — имена, которые нужно вырезать: имя файла движка и название
/// продукта, прочитанное из ресурсов самого движка. Своего списка брендов
/// в коде нет: вырезается ровно то, чем движок себя называет, включая
/// локализованные названия.
///
/// `None` означает «трогать не нужно»: в заголовке нет имени движка, значит
/// это обычный заголовок страницы.
///
/// ```text
/// "Новая вкладка - Google Chrome" → "Новая вкладка — FousBrowser"
/// "Google Chrome"                 → "FousBrowser — Рабочий"
/// "Новая вкладка"                 → None
/// ```
pub fn retitle(current: &str, brand_names: &[String], profile_name: &str) -> Option<String> {
    let markers: Vec<String> = brand_names
        .iter()
        .flat_map(|name| {
            let trimmed = name.trim();
            // Имя файла приходит с расширением, название продукта — без.
            let without_extension = trimmed
                .trim_end_matches(".exe")
                .trim_end_matches(".bin")
                .to_lowercase();
            [trimmed.to_lowercase(), without_extension]
        })
        .filter(|marker| marker.len() >= 3)
        .collect();

    if markers.is_empty() {
        return None;
    }

    let lowered = current.to_lowercase();
    if !markers.iter().any(|marker| lowered.contains(marker)) {
        return None;
    }

    // Заголовок движка собирается как «страница - Продукт Вендора»:
    // отбрасываем части, в которых встречается чужое имя. Сначала все
    // варианты разделителя приводятся к одному служебному символу, иначе
    // разбор по символам разрезал бы заголовок по пробелам.
    let mut normalized = current.to_string();
    for separator in TITLE_SEPARATORS {
        normalized = normalized.replace(separator, "\u{1}");
    }

    let parts: Vec<&str> = normalized
        .split('\u{1}')
        .map(str::trim)
        .filter(|part| !part.is_empty())
        .filter(|part| {
            let part = part.to_lowercase();
            !markers.iter().any(|marker| part.contains(marker))
        })
        .collect();

    let base = parts.join(" — ");
    let title = if base.is_empty() {
        format!("FousBrowser — {profile_name}")
    } else if base.to_lowercase() == "fousbrowser" {
        // Наша стартовая страница называется FousBrowser: удваивать имя
        // в заголовке незачем.
        "FousBrowser".to_string()
    } else if base.to_lowercase().contains("fousbrowser") {
        base
    } else {
        format!("{base} — FousBrowser")
    };

    if title == current {
        return None;
    }
    Some(title)
}

mod windows {
    //! Минимальные объявления Win32: тянем только те функции, что нужны
    //! для оформления и закрытия окна. Отдельная библиотека ради десятка
    //! вызовов не нужна.

    use std::ffi::c_void;
    use std::sync::atomic::{AtomicIsize, Ordering};

    use super::{retitle, APPEAR_TRIES, POLL};

    type Hwnd = *mut c_void;
    type Hicon = *mut c_void;

    const WM_SETICON: u32 = 0x0080;
    const WM_CLOSE: u32 = 0x0010;
    const ICON_SMALL: usize = 0;
    const ICON_BIG: usize = 1;
    const GW_OWNER: u32 = 4;

    #[link(name = "user32")]
    extern "system" {
        fn EnumWindows(callback: extern "system" fn(Hwnd, isize) -> i32, lparam: isize) -> i32;
        fn GetWindowThreadProcessId(hwnd: Hwnd, process_id: *mut u32) -> u32;
        fn IsWindow(hwnd: Hwnd) -> i32;
        fn IsWindowVisible(hwnd: Hwnd) -> i32;
        fn GetWindow(hwnd: Hwnd, command: u32) -> Hwnd;
        fn GetWindowTextLengthW(hwnd: Hwnd) -> i32;
        fn GetWindowTextW(hwnd: Hwnd, text: *mut u16, max: i32) -> i32;
        fn SendMessageW(hwnd: Hwnd, message: u32, wparam: usize, lparam: isize) -> isize;
        fn PostMessageW(hwnd: Hwnd, message: u32, wparam: usize, lparam: isize) -> i32;
        fn SetWindowTextW(hwnd: Hwnd, text: *const u16) -> i32;
        fn ExtractIconW(instance: *mut c_void, file: *const u16, index: i32) -> Hicon;
    }

    /// Что ищем: главное видимое окно указанного процесса.
    struct Search {
        pid: u32,
        found: Hwnd,
    }

    extern "system" fn visit(hwnd: Hwnd, lparam: isize) -> i32 {
        // Указатель пришёл из `EnumWindows` и живёт до конца обхода.
        let search = unsafe { &mut *(lparam as *mut Search) };
        let mut owner = 0u32;
        unsafe { GetWindowThreadProcessId(hwnd, &mut owner) };
        let visible = unsafe { IsWindowVisible(hwnd) } == 1;
        let top_level = unsafe { GetWindow(hwnd, GW_OWNER) }.is_null();
        if owner == search.pid && visible && top_level {
            search.found = hwnd;
            // Ноль останавливает обход: первое подходящее окно и есть главное.
            return 0;
        }
        1
    }

    pub(super) fn find_main_window(pid: u32) -> Option<Hwnd> {
        let mut search = Search {
            pid,
            found: std::ptr::null_mut(),
        };
        unsafe { EnumWindows(visit, &mut search as *mut Search as isize) };
        if search.found.is_null() {
            None
        } else {
            Some(search.found)
        }
    }

    fn is_window(hwnd: isize) -> bool {
        (unsafe { IsWindow(hwnd as Hwnd) }) != 0
    }

    fn current_title(hwnd: isize) -> Option<String> {
        let length = unsafe { GetWindowTextLengthW(hwnd as Hwnd) };
        if length <= 0 {
            return None;
        }
        let mut buffer = vec![0u16; length as usize + 1];
        let written =
            unsafe { GetWindowTextW(hwnd as Hwnd, buffer.as_mut_ptr(), buffer.len() as i32) };
        if written <= 0 {
            return None;
        }
        buffer.truncate(written as usize);
        String::from_utf16(&buffer).ok()
    }

    fn set_title(hwnd: isize, title: &str) {
        let text: Vec<u16> = title.encode_utf16().chain(std::iter::once(0)).collect();
        unsafe { SetWindowTextW(hwnd as Hwnd, text.as_ptr()) };
    }

    /// Значок проекта, извлечённый из файла лаунчера.
    fn project_icon() -> Hicon {
        let Ok(executable) = std::env::current_exe() else {
            return std::ptr::null_mut();
        };
        let path: Vec<u16> = executable
            .to_string_lossy()
            .encode_utf16()
            .chain(std::iter::once(0))
            .collect();
        let icon = unsafe { ExtractIconW(std::ptr::null_mut(), path.as_ptr(), 0) };
        // 0 — значков нет, 1 — файл не является программой.
        if icon.is_null() || icon as isize == 1 {
            return std::ptr::null_mut();
        }
        icon
    }

    fn set_icon(hwnd: isize, icon: Hicon) {
        if icon.is_null() {
            return;
        }
        unsafe {
            SendMessageW(hwnd as Hwnd, WM_SETICON, ICON_BIG, icon as isize);
            SendMessageW(hwnd as Hwnd, WM_SETICON, ICON_SMALL, icon as isize);
        }
    }

    /// Просит окно закрыться: то же, что нажатие крестика.
    pub fn close_window(hwnd: isize) -> bool {
        if !is_window(hwnd) {
            return false;
        }
        (unsafe { PostMessageW(hwnd as Hwnd, WM_CLOSE, 0, 0) }) != 0
    }

    /// Следит за окном профиля: оформляет его и снимает чужое имя.
    pub(super) fn manage(pid: u32, profile_name: &str, engine_stem: &str, handle: &AtomicIsize) {
        let icon = project_icon();
        // Чужие имена, которые нужно вырезать из заголовка: имя файла движка
        // и его настоящее название из ресурсов (в том числе локализованное).
        let mut names = vec![engine_stem.to_string()];
        if let Some(product) = engine_product_name(pid) {
            names.push(product);
        }
        let mut window: isize = 0;
        let mut tries = 0usize;

        loop {
            if window == 0 {
                match find_main_window(pid) {
                    Some(found) => {
                        window = found as isize;
                        handle.store(window, Ordering::SeqCst);
                        set_icon(window, icon);
                        if let Some(title) = current_title(window) {
                            if let Some(branded) = retitle(&title, &names, profile_name) {
                                set_title(window, &branded);
                            }
                        }
                    }
                    None => {
                        tries += 1;
                        if tries > APPEAR_TRIES {
                            // Окно так и не появилось: движок мог завершиться.
                            return;
                        }
                    }
                }
            } else if !is_window(window) {
                handle.store(0, Ordering::SeqCst);
                return;
            } else {
                // Движок возвращает свой заголовок после загрузки страниц,
                // поэтому имя вендора вырезается повторно.
                if let Some(title) = current_title(window) {
                    if let Some(branded) = retitle(&title, &names, profile_name) {
                        set_title(window, &branded);
                    }
                }
                set_icon(window, icon);
            }

            std::thread::sleep(POLL);
        }
    }

    /// Название продукта из ресурсов движка.
    ///
    /// Своего списка брендов лаунчер не держит: он читает то имя, которым
    /// движок называет себя сам. Это работает и с локализованными сборками,
    /// где название записано не латиницей.
    fn engine_product_name(pid: u32) -> Option<String> {
        let executable = crate::engine::process::executable_of(pid)?;
        product_name(&executable)
    }

    /// Читает `ProductName` из таблицы версии файла.
    fn product_name(path: &std::path::Path) -> Option<String> {
        use std::ffi::c_void;

        #[link(name = "version")]
        extern "system" {
            fn GetFileVersionInfoSizeW(file: *const u16, handle: *mut u32) -> u32;
            fn GetFileVersionInfoW(
                file: *const u16,
                handle: u32,
                length: u32,
                data: *mut c_void,
            ) -> i32;
            fn VerQueryValueW(
                block: *const c_void,
                sub_block: *const u16,
                buffer: *mut *mut c_void,
                length: *mut u32,
            ) -> i32;
        }

        let file: Vec<u16> = path
            .to_string_lossy()
            .encode_utf16()
            .chain(std::iter::once(0))
            .collect();
        let mut handle = 0u32;
        let size = unsafe { GetFileVersionInfoSizeW(file.as_ptr(), &mut handle) };
        if size == 0 {
            return None;
        }

        let mut data = vec![0u8; size as usize];
        if unsafe {
            GetFileVersionInfoW(
                file.as_ptr(),
                handle,
                size,
                data.as_mut_ptr() as *mut c_void,
            )
        } == 0
        {
            return None;
        }

        // Языки и кодовые страницы, для которых в файле есть строки.
        let mut translations: Vec<(u16, u16)> = Vec::new();
        let mut pointer: *mut c_void = std::ptr::null_mut();
        let mut length = 0u32;
        let query: Vec<u16> = "\\VarFileInfo\\Translation"
            .encode_utf16()
            .chain(std::iter::once(0))
            .collect();
        if unsafe {
            VerQueryValueW(
                data.as_ptr() as *const c_void,
                query.as_ptr(),
                &mut pointer,
                &mut length,
            )
        } != 0
            && !pointer.is_null()
        {
            let count = length as usize / 4;
            for index in 0..count {
                let pair = unsafe {
                    std::slice::from_raw_parts((pointer as *const u16).add(index * 2), 2)
                };
                translations.push((pair[0], pair[1]));
            }
        }
        if translations.is_empty() {
            // Английский (США), Unicode — самый частый случай.
            translations.push((0x0409, 0x04B0));
        }

        for (language, codepage) in translations {
            let query = format!("\\StringFileInfo\\{language:04x}{codepage:04x}\\ProductName");
            let query: Vec<u16> = query.encode_utf16().chain(std::iter::once(0)).collect();
            let mut value: *mut c_void = std::ptr::null_mut();
            let mut value_length = 0u32;
            if unsafe {
                VerQueryValueW(
                    data.as_ptr() as *const c_void,
                    query.as_ptr(),
                    &mut value,
                    &mut value_length,
                )
            } == 0
                || value.is_null()
                || value_length == 0
            {
                continue;
            }
            let units =
                unsafe { std::slice::from_raw_parts(value as *const u16, value_length as usize) };
            let text = String::from_utf16_lossy(units)
                .trim_end_matches('\0')
                .trim()
                .to_string();
            if !text.is_empty() {
                return Some(text);
            }
        }
        None
    }

    /// Проверка для тестов: описатель окна по процессу.
    #[allow(dead_code)]
    pub(super) fn window_of(pid: u32) -> isize {
        find_main_window(pid).map(|hwnd| hwnd as isize).unwrap_or(0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn names(list: &[&str]) -> Vec<String> {
        list.iter().map(|name| name.to_string()).collect()
    }

    #[test]
    fn vendor_name_is_replaced_by_ours() {
        let chrome = names(&["chrome", "Google Chrome"]);
        assert_eq!(
            retitle("Новая вкладка - Google Chrome", &chrome, "Рабочий").as_deref(),
            Some("Новая вкладка — FousBrowser")
        );
        assert_eq!(
            retitle("Google Chrome", &chrome, "Рабочий").as_deref(),
            Some("FousBrowser — Рабочий")
        );
    }

    #[test]
    fn localized_product_name_is_replaced_too() {
        // Название продукта читается из ресурсов движка, поэтому работает
        // и для сборок, где оно записано не латиницей.
        let localized = names(&["browser", "Яндекс Браузер"]);
        assert_eq!(
            retitle("Почта - Яндекс Браузер", &localized, "Рабочий").as_deref(),
            Some("Почта — FousBrowser")
        );
    }

    #[test]
    fn titles_without_the_engine_name_are_untouched() {
        let chrome = names(&["chrome", "Google Chrome"]);
        assert_eq!(retitle("Новая вкладка", &chrome, "Рабочий"), None);
        assert_eq!(retitle("Документация проекта", &chrome, "Рабочий"), None);
        assert_eq!(retitle("что-то", &names(&[""]), "Рабочий"), None);
        assert_eq!(retitle("что-то", &[], "Рабочий"), None);
    }

    #[test]
    fn a_title_with_spaces_is_not_split_into_words() {
        let chrome = names(&["chrome", "Google Chrome"]);
        // Разделителем считается только « - », а не любой пробел или дефис.
        assert_eq!(
            retitle("Мои закладки - Google Chrome", &chrome, "Рабочий").as_deref(),
            Some("Мои закладки — FousBrowser")
        );
        assert_eq!(
            retitle("Почта — важное - Google Chrome", &chrome, "Рабочий").as_deref(),
            Some("Почта — важное — FousBrowser")
        );
    }

    #[test]
    fn retitle_is_idempotent() {
        let chrome = names(&["chrome", "Google Chrome"]);
        let once = retitle("Новая вкладка - Google Chrome", &chrome, "Рабочий").unwrap();
        assert_eq!(once, "Новая вкладка — FousBrowser");

        // Повторная обработка уже нашего заголовка ничего не меняет.
        let ours = names(&["fousbrowser", "FousBrowser"]);
        assert_eq!(retitle(&once, &ours, "Рабочий"), None);
    }

    #[test]
    fn our_own_start_page_keeps_a_single_name() {
        // Заголовок стартовой страницы — тоже FousBrowser: удвоения быть не должно.
        let chrome = names(&["chrome", "Google Chrome"]);
        assert_eq!(
            retitle("FousBrowser - Google Chrome", &chrome, "Рабочий").as_deref(),
            Some("FousBrowser")
        );
    }

    #[test]
    fn our_own_engine_gets_no_foreign_name() {
        // Для собственного движка (Фаза B) имя файла и название продукта —
        // наши, поэтому чужого названия в заголовке не появляется.
        let ours = names(&["fousbrowser", "FousBrowser"]);
        assert_eq!(retitle("Новая вкладка", &ours, "Рабочий"), None);
    }
}
