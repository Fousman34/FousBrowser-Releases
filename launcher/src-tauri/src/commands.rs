//! IPC-команды лаунчера. Этап M1: только хранилище.
//!
//! Команды объявлены `async`, чтобы вывод ключа Argon2id (256 МиБ, порядка
//! секунды) не блокировал поток, обслуживающий интерфейс. Тяжёлую работу
//! стоит в будущем вынести в `spawn_blocking`, но и текущий вариант не
//! подвешивает окно.

use std::sync::Mutex;

use serde::Serialize;
use tauri::State;

use crate::paths;
use crate::vault::kdf::PasswordReport;
use crate::vault::{AttemptsState, UnlockedVault, Vault, VaultError, WARN_AT_ATTEMPTS};

/// Состояние приложения: разблокированное хранилище, если оно открыто.
#[derive(Default)]
pub struct VaultState {
    inner: Mutex<Option<UnlockedVault>>,
}

impl VaultState {
    fn replace(&self, vault: Option<UnlockedVault>) {
        // Отравленный мьютекс восстанавливаем: доступ к хранилищу важнее паники.
        let mut guard = self
            .inner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        *guard = vault;
    }

    fn is_unlocked(&self) -> bool {
        let guard = self
            .inner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        guard.is_some()
    }

    fn with_unlocked<T>(&self, f: impl FnOnce(&UnlockedVault) -> T) -> Option<T> {
        let guard = self
            .inner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        guard.as_ref().map(f)
    }

    fn with_unlocked_mut<T>(&self, f: impl FnOnce(&mut UnlockedVault) -> T) -> Option<T> {
        let mut guard = self
            .inner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        guard.as_mut().map(f)
    }
}

/// Ошибка, пригодная для разбора на стороне интерфейса.
#[derive(Debug, Serialize)]
pub struct CommandError {
    /// Машиночитаемый вид ошибки.
    pub kind: String,
    /// Текст для показа пользователю.
    pub message: String,
    /// Сколько секунд ждать (для `backoff`).
    pub seconds: Option<u64>,
    /// Сколько было неудачных попыток (для `confirmation_required`).
    pub attempts: Option<u32>,
}

impl CommandError {
    fn new(kind: &str, message: impl Into<String>) -> Self {
        Self {
            kind: kind.to_string(),
            message: message.into(),
            seconds: None,
            attempts: None,
        }
    }
}

impl From<VaultError> for CommandError {
    fn from(error: VaultError) -> Self {
        let kind = match &error {
            VaultError::NotFound(_) => "not_found",
            VaultError::AlreadyExists(_) => "already_exists",
            VaultError::WrongPassword => "wrong_password",
            VaultError::WeakPassword(_) => "weak_password",
            VaultError::Corrupted(_) => "corrupted",
            VaultError::Locked => "locked",
            VaultError::Backoff { .. } => "backoff",
            VaultError::ConfirmationRequired { .. } => "confirmation_required",
            VaultError::Io(_) => "io",
            VaultError::Json(_) => "json",
            VaultError::Crypto(_) => "crypto",
        };

        let mut payload = Self::new(kind, error.to_string());
        match error {
            VaultError::Backoff { seconds } => payload.seconds = Some(seconds),
            VaultError::ConfirmationRequired { attempts } => payload.attempts = Some(attempts),
            _ => {}
        }
        payload
    }
}

impl From<std::io::Error> for CommandError {
    fn from(error: std::io::Error) -> Self {
        Self::new("io", format!("ошибка доступа к файлам: {error}"))
    }
}

pub type CommandResult<T> = std::result::Result<T, CommandError>;

/// Состояние хранилища для экрана входа.
#[derive(Debug, Serialize)]
pub struct VaultStatus {
    /// Создано ли хранилище на этом устройстве.
    pub exists: bool,
    /// Разблокировано ли оно в текущей сессии.
    pub unlocked: bool,
    /// Каталог хранилища (для диагностики).
    pub vault_path: String,
    /// Минимальная длина мастер-пароля.
    pub password_min_length: usize,
    /// Неудачных попыток подряд.
    pub failed_attempts: u32,
    /// Пора показать предупреждение о раскладке клавиатуры.
    pub warn_attempts: bool,
    /// Требуется явное подтверждение продолжения.
    pub confirm_required: bool,
    /// Сколько секунд осталось до следующей попытки.
    pub backoff_seconds: u64,
}

/// Результат успешного создания или разблокировки.
#[derive(Debug, Serialize)]
pub struct UnlockOutcome {
    pub vault_id: String,
    /// Сколько профилей в хранилище (до расшифровки недоступно).
    pub profiles: usize,
    /// Предупреждения для показа пользователю.
    pub warnings: Vec<String>,
}

/// Собирает состояние хранилища. Общая реализация для двух команд,
/// чтобы не вызывать одну команду Tauri из другой.
async fn status_impl(state: &VaultState) -> CommandResult<VaultStatus> {
    let dir = paths::vault_dir()?;
    let exists = Vault::exists(&dir);
    let now = crate::vault::unix_now();

    let (failed_attempts, confirm_required, backoff_seconds) = if exists {
        let attempts = Vault::open(&dir)?.attempts();
        (
            attempts.failed,
            attempts.confirm_required,
            attempts.remaining_backoff(now),
        )
    } else {
        (0, false, 0)
    };

    Ok(VaultStatus {
        exists,
        unlocked: state.is_unlocked(),
        vault_path: dir.display().to_string(),
        password_min_length: crate::vault::kdf::MIN_PASSWORD_LEN,
        failed_attempts,
        warn_attempts: failed_attempts >= WARN_AT_ATTEMPTS,
        confirm_required,
        backoff_seconds,
    })
}

/// Оценка пароля для индикатора сложности. Ничего не создаёт и не меняет.
#[tauri::command]
pub fn password_report(password: String) -> PasswordReport {
    crate::vault::check_password(&password)
}

/// Текущее состояние хранилища.
#[tauri::command]
pub async fn vault_status(state: State<'_, VaultState>) -> CommandResult<VaultStatus> {
    status_impl(&state).await
}

/// Создаёт хранилище и сразу разблокирует его.
#[tauri::command]
pub async fn vault_create(
    password: String,
    state: State<'_, VaultState>,
) -> CommandResult<UnlockOutcome> {
    let dir = paths::vault_dir()?;
    let unlocked = Vault::create(&dir, &password)?;
    let outcome = UnlockOutcome {
        vault_id: unlocked.vault_id().to_string(),
        profiles: unlocked.metadata().profile_count(),
        warnings: vec![
            "Восстановления пароля не существует: ключ выводится из пароля и нигде не хранится."
                .to_string(),
            "Сохраните пароль в менеджере паролей.".to_string(),
        ],
    };
    state.replace(Some(unlocked));
    Ok(outcome)
}

/// Разблокирует существующее хранилище.
#[tauri::command]
pub async fn vault_unlock(
    password: String,
    state: State<'_, VaultState>,
) -> CommandResult<UnlockOutcome> {
    let dir = paths::vault_dir()?;
    let vault = Vault::open(&dir)?;
    let unlocked = vault.unlock(&password)?;

    let mut warnings = Vec::new();
    if unlocked.metadata().settings.remind_backup {
        warnings.push(
            "Резервной копии хранилища нет. Пароль восстановить нельзя — сделайте экспорт."
                .to_string(),
        );
    }

    let outcome = UnlockOutcome {
        vault_id: unlocked.vault_id().to_string(),
        profiles: unlocked.metadata().profile_count(),
        warnings,
    };
    state.replace(Some(unlocked));
    Ok(outcome)
}

/// Блокирует хранилище: мастер-ключ затирается в памяти.
#[tauri::command]
pub async fn vault_lock(state: State<'_, VaultState>) -> CommandResult<()> {
    state.replace(None);
    Ok(())
}

/// Подтверждает продолжение попыток после достижения порога.
///
/// Данные при этом не трогаются, счётчик неудач не обнуляется.
#[tauri::command]
pub async fn vault_confirm_continue(state: State<'_, VaultState>) -> CommandResult<VaultStatus> {
    let dir = paths::vault_dir()?;
    if Vault::exists(&dir) {
        Vault::open(&dir)?.confirm_continue()?;
    }
    status_impl(&state).await
}

/// Текущее состояние счётчика попыток.
#[tauri::command]
pub async fn vault_attempts() -> CommandResult<AttemptsState> {
    let dir = paths::vault_dir()?;
    if !Vault::exists(&dir) {
        return Ok(AttemptsState::new(""));
    }
    Ok(Vault::open(&dir)?.attempts())
}

/// Сохраняет метаданные после правок. Возвращает число профилей.
#[tauri::command]
pub async fn vault_save_metadata(state: State<'_, VaultState>) -> CommandResult<usize> {
    state
        .with_unlocked_mut(|vault| vault.save_metadata())
        .ok_or_else(|| CommandError::new("locked", "хранилище заблокировано"))??;

    Ok(state
        .with_unlocked(|vault| vault.metadata().profile_count())
        .unwrap_or(0))
}
