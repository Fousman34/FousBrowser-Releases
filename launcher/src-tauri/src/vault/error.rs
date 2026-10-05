//! Ошибки хранилища.
//!
//! Осознанно НЕ существует варианта ошибки «данные удалены за неудачные
//! попытки»: политика проекта — неудачный ввод пароля не приводит к потере
//! данных ни при каком количестве попыток.

use thiserror::Error;

pub type Result<T> = std::result::Result<T, VaultError>;

#[derive(Debug, Error)]
pub enum VaultError {
    #[error("хранилище не найдено: {0}")]
    NotFound(String),

    #[error("хранилище уже существует: {0}")]
    AlreadyExists(String),

    #[error("неверный мастер-пароль")]
    WrongPassword,

    #[error("мастер-пароль не соответствует требованиям: {0}")]
    WeakPassword(String),

    #[error("хранилище повреждено: {0}")]
    Corrupted(String),

    #[error("хранилище заблокировано")]
    Locked,

    #[error("{0}")]
    Invalid(String),

    #[error("ввод временно недоступен: подождите {seconds} с")]
    Backoff { seconds: u64 },

    #[error(
        "после {attempts} неудачных попыток требуется явное подтверждение продолжения. \
         Данные не удалены — нажмите «Продолжить попытки»"
    )]
    ConfirmationRequired { attempts: u32 },

    #[error("ошибка ввода-вывода: {0}")]
    Io(#[from] std::io::Error),

    #[error("движок не установлен: {0}")]
    EngineMissing(String),

    #[error("движок не удалось запустить: {0}")]
    EngineFailed(String),

    #[error("профиль уже запущен: {0}")]
    AlreadyRunning(String),

    #[error("профиль не запущен: {0}")]
    NotRunning(String),

    #[error("ошибка формата данных: {0}")]
    Json(#[from] serde_json::Error),

    #[error("криптографическая ошибка: {0}")]
    Crypto(&'static str),
}
