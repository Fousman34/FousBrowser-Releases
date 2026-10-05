//! FousBrowser launcher.
//!
//! Лаунчер — не браузер. Он управляет зашифрованными профилями, запускает
//! под ними браузерные движки, шифрует данные на диске и проверяет обновления.
//!
//! Этап M1: хранилище (Argon2id, XChaCha20-Poly1305, метаданные, вход).

mod commands;
mod paths;
mod vault;

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
        ])
        .run(tauri::generate_context!())
        .expect("не удалось запустить FousBrowser");
}
