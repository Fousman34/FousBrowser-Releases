//! IPC-команды лаунчера. Этап M1: только хранилище.
//!
//! Команды объявлены `async`, чтобы вывод ключа Argon2id (256 МиБ, порядка
//! секунды) не блокировал поток, обслуживающий интерфейс. Тяжёлую работу
//! стоит в будущем вынести в `spawn_blocking`, но и текущий вариант не
//! подвешивает окно.

use std::sync::Mutex;

use serde::{Deserialize, Serialize};
use tauri::State;

use crate::paths;
use crate::vault::kdf::PasswordReport;
use crate::vault::{
    AttemptsState, ProfileKind, ProfileMeta, ProxyConfig, ProxyScheme, UnlockedVault, Vault,
    VaultError, WARN_AT_ATTEMPTS,
};

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
            VaultError::Invalid(_) => "invalid",
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

// --- профили ---------------------------------------------------------------

/// Выполняет операцию над открытым хранилищем.
///
/// Если хранилище заблокировано, команда не падает и не пытается ничего
/// расшифровать: она возвращает понятную ошибку, а интерфейс показывает
/// экран ввода пароля.
fn with_vault<T>(
    state: &VaultState,
    f: impl FnOnce(&UnlockedVault) -> CommandResult<T>,
) -> CommandResult<T> {
    state.with_unlocked(f).unwrap_or_else(locked)
}

fn with_vault_mut<T>(
    state: &VaultState,
    f: impl FnOnce(&mut UnlockedVault) -> CommandResult<T>,
) -> CommandResult<T> {
    state.with_unlocked_mut(f).unwrap_or_else(locked)
}

fn locked<T>() -> CommandResult<T> {
    Err(CommandError::new("locked", "хранилище заблокировано"))
}

/// Настройки прокси в том виде, в каком их видит интерфейс.
///
/// Пароль сюда не попадает: он не нужен для отображения, а каждое лишнее
/// место, где секрет покидает ядро, — лишний риск.
#[derive(Debug, Serialize)]
pub struct ProxyView {
    pub scheme: String,
    pub host: String,
    pub port: u16,
    pub username: Option<String>,
    /// Задан ли пароль. Сам пароль остаётся в зашифрованных метаданных.
    pub has_password: bool,
}

/// Профиль для интерфейса.
#[derive(Debug, Serialize)]
pub struct ProfileView {
    pub id: String,
    pub name: String,
    pub kind: String,
    pub seed: u32,
    pub created_unix: u64,
    pub engine_version: Option<String>,
    pub note: Option<String>,
    pub proxy: Option<ProxyView>,
}

impl From<&ProfileMeta> for ProfileView {
    fn from(profile: &ProfileMeta) -> Self {
        Self {
            id: profile.id.clone(),
            name: profile.name.clone(),
            kind: profile.kind.as_str().to_string(),
            seed: profile.seed,
            created_unix: profile.created_unix,
            engine_version: profile.engine_version.clone(),
            note: profile.note.clone(),
            proxy: profile.proxy.as_ref().map(|config| ProxyView {
                scheme: config.scheme.as_str().to_string(),
                host: config.host.clone(),
                port: config.port,
                username: config.username.clone(),
                has_password: config.password.is_some(),
            }),
        }
    }
}

/// Настройки прокси, приходящие из интерфейса.
#[derive(Debug, Deserialize)]
pub struct ProxyInput {
    pub scheme: String,
    pub host: String,
    pub port: u16,
    #[serde(default)]
    pub username: Option<String>,
    #[serde(default)]
    pub password: Option<String>,
}

/// Преобразует ввод интерфейса в настройки прокси.
///
/// Если пароль не передан, а имя пользователя не изменилось, сохраняется
/// прежний пароль: человек, поменявший только порт, не должен вводить
/// секрет заново. Пустая строка означает «пароля нет».
fn merge_proxy(
    current: Option<&ProxyConfig>,
    input: Option<ProxyInput>,
) -> CommandResult<Option<ProxyConfig>> {
    let Some(input) = input else {
        return Ok(None);
    };

    let scheme: ProxyScheme = input
        .scheme
        .parse()
        .map_err(|message: String| CommandError::new("invalid", message))?;

    let username = input
        .username
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty());

    let password = match input.password {
        Some(value) if value.is_empty() => None,
        Some(value) => Some(value),
        None => current
            .filter(|config| config.username == username)
            .and_then(|config| config.password.clone()),
    };

    Ok(Some(ProxyConfig {
        scheme,
        host: input.host.trim().to_string(),
        port: input.port,
        // Пароль без имени пользователя не имеет смысла.
        username: username.clone(),
        password: if username.is_some() { password } else { None },
    }))
}

/// Разбор типа профиля из строки интерфейса.
fn parse_kind(value: &str) -> CommandResult<ProfileKind> {
    value
        .parse()
        .map_err(|message: String| CommandError::new("invalid", message))
}

/// Список профилей. Без открытого хранилища вернуть его нечем.
#[tauri::command]
pub async fn profile_list(state: State<'_, VaultState>) -> CommandResult<Vec<ProfileView>> {
    with_vault(&state, |vault| {
        Ok(vault.profiles().iter().map(ProfileView::from).collect())
    })
}

/// Создаёт профиль.
#[tauri::command]
pub async fn profile_create(
    name: String,
    kind: String,
    proxy: Option<ProxyInput>,
    note: Option<String>,
    state: State<'_, VaultState>,
) -> CommandResult<ProfileView> {
    let kind = parse_kind(&kind)?;
    with_vault_mut(&state, |vault| {
        let config = merge_proxy(None, proxy)?;
        let profile = vault.create_profile(&name, kind, config, note)?;
        Ok(ProfileView::from(&profile))
    })
}

/// Клонирует профиль: те же настройки, новое зерно отпечатка.
#[tauri::command]
pub async fn profile_clone(
    profile_id: String,
    name: Option<String>,
    state: State<'_, VaultState>,
) -> CommandResult<ProfileView> {
    with_vault_mut(&state, |vault| {
        let profile = vault.clone_profile(&profile_id, name.as_deref())?;
        Ok(ProfileView::from(&profile))
    })
}

/// Меняет имя, тип и заметку профиля.
#[tauri::command]
pub async fn profile_update(
    profile_id: String,
    name: String,
    kind: String,
    note: Option<String>,
    state: State<'_, VaultState>,
) -> CommandResult<ProfileView> {
    let kind = parse_kind(&kind)?;
    with_vault_mut(&state, |vault| {
        let profile = vault.update_profile(&profile_id, &name, kind, note)?;
        Ok(ProfileView::from(&profile))
    })
}

/// Привязывает прокси к профилю или снимает привязку.
#[tauri::command]
pub async fn profile_set_proxy(
    profile_id: String,
    proxy: Option<ProxyInput>,
    state: State<'_, VaultState>,
) -> CommandResult<ProfileView> {
    with_vault_mut(&state, |vault| {
        let current = vault
            .metadata()
            .find(&profile_id)
            .ok_or_else(|| CommandError::new("not_found", format!("профиль {profile_id}")))?
            .proxy
            .clone();
        let config = merge_proxy(current.as_ref(), proxy)?;
        let profile = vault.set_proxy(&profile_id, config)?;
        Ok(ProfileView::from(&profile))
    })
}

/// Удаляет профиль и безвозвратно стирает его данные.
///
/// Возвращает число оставшихся профилей.
#[tauri::command]
pub async fn profile_delete(
    profile_id: String,
    state: State<'_, VaultState>,
) -> CommandResult<usize> {
    with_vault_mut(&state, |vault| {
        vault.delete_profile(&profile_id)?;
        Ok(vault.profiles().len())
    })
}
