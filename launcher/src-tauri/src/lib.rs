//! FousBrowser launcher.
//!
//! Лаунчер — не браузер. Он управляет зашифрованными профилями, запускает
//! под ними браузерные движки, шифрует данные на диске и проверяет обновления.
//!
//! Этап M1: хранилище (Argon2id, XChaCha20-Poly1305, метаданные, вход).
//! Этап M3: профили — создание, клонирование, правка, удаление, прокси.

mod commands;

/// Определение пользовательских каталогов.
pub mod paths;

/// Шифрованное хранилище: ключи, метаданные, профили.
///
/// Модуль публичный: это ядро лаунчера, и часть его поверхности
/// (`profiles_dir`, `temp_dir`, `random_seed`, `find`) начинает
/// использоваться на этапах M3–M5.
pub mod vault;

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_opener::init())
        .manage(commands::VaultState::default())
        .invoke_handler(tauri::generate_handler![
            commands::password_report,
            commands::vault_status,
            commands::vault_create,
            commands::vault_unlock,
            commands::vault_lock,
            commands::vault_confirm_continue,
            commands::vault_attempts,
            commands::vault_save_metadata,
            commands::profile_list,
            commands::profile_create,
            commands::profile_clone,
            commands::profile_update,
            commands::profile_set_proxy,
            commands::profile_delete,
        ])
        .run(tauri::generate_context!())
        .expect("не удалось запустить FousBrowser");
}
