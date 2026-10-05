//! FousBrowser launcher.
//!
//! Лаунчер — не браузер. Он управляет зашифрованными профилями, запускает
//! под ними браузерные движки, шифрует данные на диске и проверяет обновления.
//!
//! Этапы: M1 — хранилище, M3 — профили, M4 — шифрование данных профиля,
//! M5 — запуск и остановка движков.

mod commands;

/// Поиск, запуск и остановка браузерных движков.
pub mod engine;

/// Определение пользовательских каталогов.
pub mod paths;

/// Локальный прокси-мост: движку — беспарольный адрес, апстриму — секрет.
pub mod proxy;

/// Шифрованное хранилище: ключи, метаданные, профили, данные профилей.
pub mod vault;

/// Обновления движков по двум независимым каналам.
pub mod updater;

use std::time::Duration;

/// Как часто проверять, не закрылся ли браузер.
const REAP_INTERVAL: Duration = Duration::from_secs(2);

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_opener::init())
        .manage(commands::VaultState::default())
        .manage(engine::EngineManager::default())
        .manage(proxy::BridgeManager::default())
        .setup(|app| {
            // Сторож: как только браузер закрылся (пользователь нажал «выход»),
            // данные профиля шифруются обратно. Интерфейс замораживать нельзя,
            // поэтому проверка идёт по таймеру в отдельной задаче.
            let handle = app.handle().clone();
            tauri::async_runtime::spawn(async move {
                loop {
                    tokio::time::sleep(REAP_INTERVAL).await;
                    commands::reap_and_finalize(&handle);
                }
            });
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            commands::password_report,
            commands::vault_status,
            commands::vault_create,
            commands::vault_unlock,
            commands::vault_lock,
            commands::vault_confirm_continue,
            commands::vault_recover,
            commands::vault_attempts,
            commands::vault_save_metadata,
            commands::profile_list,
            commands::profile_transfer,
            commands::profile_check_proxy,
            commands::profile_create,
            commands::profile_clone,
            commands::profile_update,
            commands::profile_set_proxy,
            commands::profile_delete,
            commands::engine_status,
            commands::profile_runtime_list,
            commands::profile_launch,
            commands::profile_stop,
            commands::profile_stop_all,
            commands::update_state,
            commands::update_check,
            commands::update_install,
            commands::app_restart,
        ])
        .run(tauri::generate_context!())
        .expect("не удалось запустить FousBrowser");
}
