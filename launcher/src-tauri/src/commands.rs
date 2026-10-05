//! IPC-команды лаунчера. Этап M1: только хранилище.
//!
//! Команды объявлены `async`, чтобы вывод ключа Argon2id (256 МиБ, порядка
//! секунды) не блокировал поток, обслуживающий интерфейс. Тяжёлую работу
//! стоит в будущем вынести в `spawn_blocking`, но и текущий вариант не
//! подвешивает окно.

use std::sync::Mutex;

use serde::{Deserialize, Serialize};
use tauri::State;

// Serialize lifecycle changes with background sealing and archive operations.
static LIFECYCLE: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());
static UPDATE_INSTALL: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

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
            VaultError::EngineMissing(_) => "engine_missing",
            VaultError::EngineFailed(_) => "engine_failed",
            VaultError::AlreadyRunning(_) => "already_running",
            VaultError::NotRunning(_) => "not_running",
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
    /// Что удалось разобрать после аварийного завершения.
    pub recovery: RecoveryReport,
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
    let _operation = LIFECYCLE.lock().await;
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
        // Новое хранилище: разбирать нечего.
        recovery: RecoveryReport::default(),
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
    let _operation = LIFECYCLE.lock().await;
    let dir = paths::vault_dir()?;
    let vault = Vault::open(&dir)?;
    let mut unlocked = vault.unlock(&password)?;

    // Разбор последствий сбоя: расшифрованные копии, оставшиеся от прошлого
    // запуска, возвращаются в контейнеры (или удаляются — по настройке).
    // Делается сразу после разблокировки, потому что раньше ключа ещё нет.
    let recovery = match crate::engine::recovery::recover(&mut unlocked) {
        Ok(report) => report,
        Err(error) => {
            let mut report = RecoveryReport::default();
            report.failed.push(crate::engine::recovery::Failure {
                profile_id: "хранилище".to_string(),
                message: crate::engine::recovery::describe(&error),
            });
            report
        }
    };

    let mut warnings = Vec::new();
    warnings.extend(recovery.notes());
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
        recovery,
    };
    state.replace(Some(unlocked));
    Ok(outcome)
}

/// Повторяет разбор последствий сбоя по требованию.
#[tauri::command]
pub async fn vault_recover(state: State<'_, VaultState>) -> CommandResult<RecoveryReport> {
    let _operation = LIFECYCLE.lock().await;
    with_vault_mut(&state, |vault| Ok(crate::engine::recovery::recover(vault)?))
}

/// Блокирует хранилище: мастер-ключ затирается в памяти.
#[tauri::command]
pub async fn vault_lock(
    state: State<'_, VaultState>,
    engines: State<'_, EngineManager>,
) -> CommandResult<()> {
    let _operation = LIFECYCLE.lock().await;
    if !engines.ids().is_empty() {
        return Err(CommandError::new(
            "already_running",
            "Сначала остановите работающие профили",
        ));
    }
    with_vault(&state, |vault| {
        for profile in vault.profiles() {
            if vault.temp_profile_dir(&profile.id).exists() {
                return Err(CommandError::new(
                    "plaintext",
                    "Сначала зашифруйте открытые данные профилей",
                ));
            }
        }
        Ok(())
    })?;
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

#[tauri::command]
pub async fn profile_transfer(
    profile_id: Option<String>,
    password: String,
    app: AppHandle,
) -> CommandResult<Option<String>> {
    let password = zeroize::Zeroizing::new(password);
    tauri::async_runtime::spawn_blocking(move || {
        let dialog = rfd::FileDialog::new().add_filter("FousBrowser profile", &["fousprofile"]);
        let selected = if profile_id.is_some() {
            dialog.set_file_name("profile.fousprofile").save_file()
        } else {
            dialog.pick_file()
        };
        let Some(path) = selected else {
            return Ok(None);
        };
        let _operation = LIFECYCLE.blocking_lock();
        let state = app.state::<VaultState>();
        with_vault_mut(&state, |vault| {
            if let Some(id) = profile_id {
                if app.state::<EngineManager>().is_running(&id) {
                    return Err(CommandError::new(
                        "already_running",
                        "Сначала остановите профиль",
                    ));
                }
                vault.export_profile(&id, &password, &path)?;
                Ok(Some("Профиль экспортирован".to_string()))
            } else {
                let profile = vault.import_profile(&password, &path)?;
                Ok(Some(format!("Импортирован профиль «{}»", profile.name)))
            }
        })
    })
    .await
    .map_err(|_| CommandError::new("transfer", "Не удалось завершить перенос профиля"))?
}

#[tauri::command]
pub async fn profile_check_proxy(
    profile_id: String,
    state: State<'_, VaultState>,
) -> CommandResult<()> {
    let config = with_vault(&state, |vault| {
        vault
            .metadata()
            .find(&profile_id)
            .and_then(|profile| profile.proxy.clone())
            .ok_or_else(|| CommandError::new("invalid", "Прокси не настроен"))
    })?;
    crate::proxy::check(&config).await?;
    Ok(())
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
    let _operation = LIFECYCLE.lock().await;
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
    let _operation = LIFECYCLE.lock().await;
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
    let _operation = LIFECYCLE.lock().await;
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
    let _operation = LIFECYCLE.lock().await;
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
    engines: State<'_, EngineManager>,
) -> CommandResult<usize> {
    let _operation = LIFECYCLE.lock().await;
    if engines.is_running(&profile_id) {
        return Err(CommandError::new(
            "already_running",
            "Сначала остановите профиль",
        ));
    }
    with_vault_mut(&state, |vault| {
        vault.delete_profile(&profile_id)?;
        Ok(vault.profiles().len())
    })
}

// --- движки и запуск профилей ----------------------------------------------
//
// Что происходит при запуске профиля:
//
// 1. данные расшифровываются из контейнера во временный каталог;
// 2. процесс движка запускается с `--user-data-dir` на этот каталог;
// 3. в журнале `vault/index.json` появляется запись «работает».
//
// При остановке порядок обратный: сначала процесс закрывается (вежливо, затем
// принудительно), и только потом данные шифруются обратно. Если запуск не
// удался, расшифрованные данные немедленно возвращаются в контейнер: лаунчер
// не оставляет открытых копий после неудачной попытки.

use crate::engine::discovery::{self, Engine};
use crate::engine::flags;
use crate::engine::journal::{Journal, STATE_RUNNING, STATE_SEALING};
use crate::engine::recovery::RecoveryReport;
use crate::engine::{EngineManager, RunningView, GRACEFUL_TIMEOUT};

use tauri::{AppHandle, Emitter, Manager};

/// Сколько ждать принудительного завершения после вежливого.
const FORCED_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(8);

/// Событие о смене состояния профиля: `profile://state`.
#[derive(Debug, Clone, Serialize)]
pub struct ProfileStateEvent {
    pub profile_id: String,
    /// `running`, `stopping`, `stopped`, `error`.
    pub state: String,
    pub pid: Option<u32>,
    pub message: Option<String>,
}

fn emit_state(
    app: &AppHandle,
    profile_id: &str,
    state: &str,
    pid: Option<u32>,
    message: Option<String>,
) {
    let payload = ProfileStateEvent {
        profile_id: profile_id.to_string(),
        state: state.to_string(),
        pid,
        message,
    };
    if let Err(error) = app.emit("profile://state", payload) {
        // Интерфейс мог быть уже закрыт: это не повод прерывать остановку,
        // иначе данные останутся расшифрованными.
        eprintln!("не удалось отправить состояние профиля: {error}");
    }
}

/// Состояние установленных движков.
#[derive(Debug, Serialize)]
pub struct EngineStatus {
    pub normal_installed: bool,
    pub normal_version: Option<String>,
    pub antidetect_installed: bool,
    pub antidetect_version: Option<String>,
}

fn describe_engine(kind: crate::vault::ProfileKind) -> (bool, Option<String>) {
    match discovery::resolve(kind) {
        Ok(engine) => (true, Some(engine.version)),
        Err(_) => (false, None),
    }
}

/// Что известно о запуске профиля и его данных.
#[derive(Debug, Serialize)]
pub struct RuntimeView {
    pub profile_id: String,
    pub running: bool,
    pub pid: Option<u32>,
    pub engine_version: Option<String>,
    pub started_unix: Option<u64>,
    /// Есть ли расшифрованная копия на диске.
    pub plaintext: bool,
    pub plaintext_entries: usize,
    pub plaintext_bytes: u64,
}

fn runtime_of(
    engines: &EngineManager,
    state: &VaultState,
    profile_id: &str,
) -> CommandResult<RuntimeView> {
    let running: Option<RunningView> = engines
        .views()
        .into_iter()
        .find(|view| view.profile_id == profile_id);

    let (plaintext, entries, bytes) = state
        .with_unlocked(|vault| vault.plaintext_state(profile_id))
        .transpose()?
        .map(|value| match value {
            crate::vault::PlaintextState::Absent => (false, 0, 0),
            crate::vault::PlaintextState::Present { entries, bytes } => (true, entries, bytes),
        })
        .unwrap_or((false, 0, 0));

    Ok(RuntimeView {
        profile_id: profile_id.to_string(),
        running: running.is_some(),
        pid: running.as_ref().map(|view| view.pid),
        engine_version: running.as_ref().map(|view| view.engine_version.clone()),
        started_unix: running.as_ref().map(|view| view.started_unix),
        plaintext,
        plaintext_entries: entries,
        plaintext_bytes: bytes,
    })
}

/// Список установленных движков.
#[tauri::command]
pub async fn engine_status() -> CommandResult<EngineStatus> {
    let (normal_installed, normal_version) = describe_engine(crate::vault::ProfileKind::Normal);
    let (antidetect_installed, antidetect_version) =
        describe_engine(crate::vault::ProfileKind::Antidetect);

    Ok(EngineStatus {
        normal_installed,
        normal_version,
        antidetect_installed,
        antidetect_version,
    })
}

/// Состояние запуска всех профилей хранилища.
#[tauri::command]
pub async fn profile_runtime_list(
    state: State<'_, VaultState>,
    engines: State<'_, EngineManager>,
) -> CommandResult<Vec<RuntimeView>> {
    let ids: Vec<String> = with_vault(&state, |vault| {
        Ok(vault
            .profiles()
            .iter()
            .map(|profile| profile.id.clone())
            .collect())
    })?;

    let mut views = Vec::with_capacity(ids.len());
    for id in ids {
        views.push(runtime_of(&engines, &state, &id)?);
    }
    Ok(views)
}

/// Шифрует расшифрованную копию профиля обратно в контейнер.
///
/// Пустая копия пропускается: незачем перезаписывать контейнер ради нуля байт.
fn seal_back(state: &VaultState, profile_id: &str) -> CommandResult<()> {
    with_vault_mut(state, |vault| {
        let temp = vault.temp_profile_dir(profile_id);
        match vault.plaintext_state(profile_id)? {
            crate::vault::PlaintextState::Absent => Ok(()),
            crate::vault::PlaintextState::Present { .. } => {
                let stats = vault.seal_profile(profile_id, &temp)?;
                if stats.vanished > 0 {
                    // Служебные файлы браузера исчезают сами: это не потеря
                    // данных пользователя, но полезно видеть в журнале.
                    eprintln!(
                        "профиль {profile_id}: во время шифрования исчезло файлов: {}",
                        stats.vanished
                    );
                }
                vault.discard_plaintext(profile_id)?;
                Ok(())
            }
        }
    })
}

/// Записывает состояние профиля в журнал.
fn journal_set(vault_dir: &std::path::Path, view: &RunningView, state: &str) -> CommandResult<()> {
    let mut journal = Journal::load(vault_dir);
    journal.upsert(view.journal_entry(state));
    journal.save(vault_dir)?;
    Ok(())
}

fn journal_remove(vault_dir: &std::path::Path, profile_id: &str) -> CommandResult<()> {
    let mut journal = Journal::load(vault_dir);
    journal.remove(profile_id);
    journal.save(vault_dir)?;
    Ok(())
}

/// Запускает профиль: расшифровывает данные и стартует движок.
#[tauri::command]
pub async fn profile_launch(
    profile_id: String,
    app: AppHandle,
    state: State<'_, VaultState>,
    engines: State<'_, EngineManager>,
    bridges: State<'_, crate::proxy::BridgeManager>,
) -> CommandResult<RuntimeView> {
    let _operation = LIFECYCLE.lock().await;
    if engines.is_running(&profile_id) {
        return Err(CommandError::new(
            "already_running",
            format!("профиль {profile_id} уже запущен"),
        ));
    }

    let profile = with_vault(&state, |vault| {
        vault
            .metadata()
            .find(&profile_id)
            .cloned()
            .ok_or_else(|| CommandError::new("not_found", format!("профиль {profile_id}")))
    })?;

    let engine: Engine = discovery::resolve(profile.kind)?;
    if let Some(config) = &profile.proxy {
        crate::proxy::check(config).await?;
    }
    let temp_dir = with_vault(&state, |vault| Ok(vault.temp_profile_dir(&profile_id)))?;

    // Прокси с логином и паролем обслуживает локальный мост: движки не умеют
    // парольную аутентификацию через `--proxy-server`. В командную строку
    // движка уходит только адрес моста, без секретов.
    let plaintext = with_vault(&state, |vault| Ok(vault.plaintext_state(&profile_id)?))?;
    if plaintext == crate::vault::PlaintextState::Absent || !temp_dir.is_dir() {
        with_vault_mut(&state, |vault| {
            vault.unseal_profile(&profile_id, &temp_dir)?;
            Ok(())
        })?;
    }

    let proxy_address = match &profile.proxy {
        None => None,
        Some(config) if flags::proxy_needs_bridge(config) => {
            match crate::proxy::Bridge::start(config.clone()).await {
                Ok(bridge) => {
                    let address = bridge.address();
                    bridges.insert(&profile_id, bridge);
                    Some(address)
                }
                Err(error) => return Err(CommandError::from(error)),
            }
        }
        Some(config) => Some(flags::proxy_address(config)),
    };

    // Стартовая страница: своя, с одной строкой поиска. Если её не удалось
    // подготовить, движок откроет свою страницу новой вкладки — это хуже,
    // но прерывать из-за оформления запуск профиля нельзя.
    let start_url = match crate::engine::startpage::ensure(&paths::app_root()?) {
        Ok(page) => Some(crate::engine::startpage::file_url(&page)),
        Err(error) => {
            eprintln!("стартовая страница недоступна: {error}");
            None
        }
    };

    let plan = flags::build(
        &profile,
        &temp_dir,
        proxy_address.as_deref(),
        start_url.as_deref(),
    );

    let launched = match engines.launch(&engine, &plan, &profile_id, temp_dir.clone()) {
        Ok(launched) => launched,
        Err(error) => {
            // Запуск не удался: открытая копия немедленно возвращается
            // в контейнер, иначе она осталась бы на диске без присмотра.
            if let Err(seal_error) = seal_back(&state, &profile_id) {
                eprintln!("не удалось зашифровать данные после неудачного запуска: {seal_error:?}");
            }
            // Мост тоже не нужен: профиль не работает.
            bridges.stop(&profile_id);
            return Err(error.into());
        }
    };
    let view = launched.view;

    let vault_dir = paths::vault_dir()?;
    journal_set(&vault_dir, &view, STATE_RUNNING)?;

    // Окно профиля должно выглядеть как FousBrowser: своё имя и свой значок.
    // Имя движка берётся из имени его файла, чтобы вырезать из заголовка
    // ровно то название, под которым движок установлен.
    let engine_stem = engine
        .program
        .file_stem()
        .map(|stem| stem.to_string_lossy().to_string())
        .unwrap_or_default();
    crate::engine::branding::start(view.pid, profile.name.clone(), engine_stem, launched.window);

    emit_state(&app, &profile_id, "running", Some(view.pid), None);

    runtime_of(&engines, &state, &profile_id)
}

/// Останавливает профиль и шифрует его данные обратно.
#[tauri::command]
pub async fn profile_stop(
    profile_id: String,
    app: AppHandle,
    state: State<'_, VaultState>,
    engines: State<'_, EngineManager>,
    bridges: State<'_, crate::proxy::BridgeManager>,
) -> CommandResult<RuntimeView> {
    let _operation = LIFECYCLE.lock().await;
    if !engines.is_running(&profile_id) {
        // Данные могли остаться расшифрованными после сбоя: возвращаем их
        // в контейнер, даже если процесса уже нет.
        seal_back(&state, &profile_id)?;
        journal_remove(&paths::vault_dir()?, &profile_id)?;
        // Мост без работающего профиля не нужен: он держал бы открытым
        // соединение к прокси от имени пользователя.
        bridges.stop(&profile_id);
        emit_state(&app, &profile_id, "stopped", None, None);
        return runtime_of(&engines, &state, &profile_id);
    }

    if let Some(view) = engines
        .views()
        .into_iter()
        .find(|view| view.profile_id == profile_id)
    {
        // Отмечаем «шифруется»: если лаунчер упадёт в этот момент, при
        // следующем запуске запись будет разобрана как осиротевшая.
        journal_set(&paths::vault_dir()?, &view, STATE_SEALING)?;
    }
    emit_state(&app, &profile_id, "stopping", None, None);

    let stopped = engines.stop(&profile_id, GRACEFUL_TIMEOUT, FORCED_TIMEOUT);
    if engines.is_running(&profile_id) {
        return Err(CommandError::new(
            "engine_failed",
            "Браузер не завершился. Данные сохранены открытыми; повторите остановку.",
        ));
    }
    bridges.stop(&profile_id);

    let result = match seal_back(&state, &profile_id) {
        Ok(()) => {
            journal_remove(&paths::vault_dir()?, &profile_id)?;
            emit_state(
                &app,
                &profile_id,
                "stopped",
                stopped.as_ref().map(|view| view.pid),
                None,
            );
            Ok(())
        }
        Err(error) => {
            emit_state(
                &app,
                &profile_id,
                "error",
                stopped.as_ref().map(|view| view.pid),
                Some(error.message.clone()),
            );
            Err(error)
        }
    };
    result?;

    runtime_of(&engines, &state, &profile_id)
}

/// Отчёт об остановке всех профилей.
#[derive(Debug, Serialize)]
pub struct StopAllReport {
    pub stopped: Vec<String>,
    pub failed: Vec<StopFailure>,
}

/// Профиль, который не удалось остановить.
#[derive(Debug, Serialize)]
pub struct StopFailure {
    pub profile_id: String,
    pub message: String,
}

/// Останавливает все профили: вежливая просьба всем сразу, затем ожидание.
#[tauri::command]
pub async fn profile_stop_all(
    app: AppHandle,
    state: State<'_, VaultState>,
    engines: State<'_, EngineManager>,
    bridges: State<'_, crate::proxy::BridgeManager>,
) -> CommandResult<StopAllReport> {
    let _operation = LIFECYCLE.lock().await;
    let ids = engines.ids();
    let vault_dir = paths::vault_dir()?;

    // Обращаемся ко всем профилям одновременно: браузеры закрываются
    // параллельно, а не по очереди.
    for id in &ids {
        if let Some(view) = engines
            .views()
            .into_iter()
            .find(|view| view.profile_id == *id)
        {
            let _ = journal_set(&vault_dir, &view, STATE_SEALING);
        }
        emit_state(&app, id, "stopping", None, None);
        let _ = engines.request_close(id);
    }

    for id in &ids {
        if engines.wait_exit(id, GRACEFUL_TIMEOUT).is_none() {
            let _ = engines.kill(id);
            let _ = engines.wait_exit(id, FORCED_TIMEOUT);
        }
    }

    let mut report = StopAllReport {
        stopped: Vec::new(),
        failed: Vec::new(),
    };

    for id in ids {
        if engines.is_running(&id) {
            report.failed.push(StopFailure {
                profile_id: id,
                message: "Браузер ещё работает; шифрование отложено".into(),
            });
            continue;
        }
        match seal_back(&state, &id) {
            Ok(()) => {
                let _ = journal_remove(&vault_dir, &id);
                bridges.stop(&id);
                emit_state(&app, &id, "stopped", None, None);
                report.stopped.push(id);
            }
            Err(error) => {
                emit_state(&app, &id, "error", None, Some(error.message.clone()));
                report.failed.push(StopFailure {
                    profile_id: id,
                    message: error.message,
                });
            }
        }
    }

    Ok(report)
}

/// Разбирает завершившиеся профили: шифрует данные и обновляет журнал.
///
/// Вызывается по таймеру. Если хранилище заперто, шифровать нечем: запись
/// остаётся в журнале, а расшифрованная копия будет разобрана при следующей
/// разблокировке (этап M7).
pub fn reap_and_finalize(app: &AppHandle) {
    let Ok(_operation) = LIFECYCLE.try_lock() else {
        return;
    };
    let engines = app.state::<EngineManager>();
    let finished = engines.reap();
    if finished.is_empty() {
        return;
    }

    let state = app.state::<VaultState>();
    let bridges = app.state::<crate::proxy::BridgeManager>();
    let Ok(vault_dir) = paths::vault_dir() else {
        return;
    };

    for view in finished {
        // Профиль завершился: мост к прокси больше не нужен.
        bridges.stop(&view.profile_id);

        if !state.is_unlocked() {
            eprintln!(
                "профиль {} завершился, но хранилище заперто: данные будут зашифрованы при разблокировке",
                view.profile_id
            );
            continue;
        }

        match seal_back(&state, &view.profile_id) {
            Ok(()) => {
                let _ = journal_remove(&vault_dir, &view.profile_id);
                emit_state(app, &view.profile_id, "stopped", Some(view.pid), None);
            }
            Err(error) => {
                emit_state(
                    app,
                    &view.profile_id,
                    "error",
                    Some(view.pid),
                    Some(error.message.clone()),
                );
            }
        }
    }
}

// --- обновления движков -----------------------------------------------------

use crate::updater::{self, Channel, Release};

/// Событие с процентом загрузки: `update://progress`.
#[derive(Debug, Clone, Serialize)]
pub struct UpdateProgressEvent {
    pub channel: String,
    pub version: String,
    pub received: u64,
    pub total: Option<u64>,
    pub percent: Option<f64>,
}

/// Строка журнала обновления: `update://log`.
#[derive(Debug, Clone, Serialize)]
pub struct UpdateLogEvent {
    pub channel: String,
    pub line: String,
}

/// Обновление завершено: `update://done`.
#[derive(Debug, Clone, Serialize)]
pub struct UpdateDoneEvent {
    pub channel: String,
    pub version: String,
    /// Путь к установленному движку.
    pub executable: String,
}

/// Обновление не удалось: `update://error`.
#[derive(Debug, Clone, Serialize)]
pub struct UpdateErrorEvent {
    pub channel: String,
    pub message: String,
}

/// Состояние канала обновлений для интерфейса.
#[derive(Debug, Serialize)]
pub struct UpdateState {
    pub channel: String,
    pub label: String,
    pub installed: Option<String>,
    /// Найденное обновление, если проверка уже выполнялась.
    pub candidate: Option<Release>,
}

fn parse_channel(value: &str) -> CommandResult<Channel> {
    match value.to_ascii_lowercase().as_str() {
        "normal" => Ok(Channel::Normal),
        "antidetect" => Ok(Channel::Antidetect),
        other => Err(CommandError::new(
            "invalid",
            format!("неизвестный канал обновлений: {other}"),
        )),
    }
}

fn update_error(error: updater::UpdateError) -> CommandError {
    let kind = match &error {
        updater::UpdateError::Network(_) => "update_network",
        updater::UpdateError::Source(_) => "update_source",
        updater::UpdateError::Insecure(_) => "update_insecure",
        updater::UpdateError::Io(_) => "io",
        updater::UpdateError::Vault(_) => "vault",
    };
    CommandError::new(kind, error.to_string())
}

/// Состояние обоих каналов: что установлено сейчас.
#[tauri::command]
pub async fn update_state() -> CommandResult<Vec<UpdateState>> {
    let mut result = Vec::new();
    for channel in [Channel::Normal, Channel::Antidetect] {
        let installed = updater::current_version(channel).map_err(update_error)?;
        result.push(UpdateState {
            channel: channel.dir_name().to_string(),
            label: channel.label().to_string(),
            installed,
            candidate: None,
        });
    }
    Ok(result)
}

/// Проверяет обновление в указанном канале.
#[tauri::command]
pub async fn update_check(channel: String) -> CommandResult<Option<Release>> {
    let channel = parse_channel(&channel)?;
    updater::check(channel).map_err(update_error)
}

/// Ставит обновление: загрузка, проверка подлинности, распаковка, установка.
///
/// Работа идёт в отдельном потоке: загрузка и проверка подписи занимают
/// время, а интерфейс должен показывать прогресс, а не ждать.
#[tauri::command]
pub async fn update_install(channel: String, version: String, app: AppHandle) -> CommandResult<()> {
    let install_guard = UPDATE_INSTALL
        .try_lock()
        .map_err(|_| CommandError::new("busy", "Установка движка уже выполняется"))?;
    let channel = parse_channel(&channel)?;
    let name = channel.dir_name().to_string();
    let app_handle = app.clone();

    std::thread::spawn(move || {
        let _install_guard = install_guard;
        let emit_log = |line: &str| {
            let _ = app_handle.emit(
                "update://log",
                UpdateLogEvent {
                    channel: name.clone(),
                    line: line.to_string(),
                },
            );
        };

        let result = updater::install_version(
            channel,
            &version,
            |progress| {
                let _ = app_handle.emit(
                    "update://progress",
                    UpdateProgressEvent {
                        channel: name.clone(),
                        version: version.clone(),
                        received: progress.received,
                        total: progress.total,
                        percent: progress.percent(),
                    },
                );
            },
            emit_log,
        );

        match result {
            Ok(executable) => {
                let _ = app_handle.emit(
                    "update://done",
                    UpdateDoneEvent {
                        channel: name,
                        version,
                        executable: executable.to_string_lossy().to_string(),
                    },
                );
            }
            Err(error) => {
                // Строка об ошибке тоже идёт в терминал: человек видит, на
                // каком шаге всё остановилось.
                emit_log(&format!("ошибка: {error}"));
                let _ = app_handle.emit(
                    "update://error",
                    UpdateErrorEvent {
                        channel: name,
                        message: error.to_string(),
                    },
                );
            }
        }
    });

    Ok(())
}

/// Перезапускает лаунчер (кнопка «Перезапустить» после обновления).
#[tauri::command]
pub async fn app_restart(app: AppHandle) -> CommandResult<()> {
    let _operation = LIFECYCLE.lock().await;
    if !app.state::<EngineManager>().ids().is_empty() {
        return Err(CommandError::new(
            "already_running",
            "Перед перезапуском остановите профили",
        ));
    }
    app.restart();
}
