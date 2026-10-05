//! Управление движками: запуск, остановка, учёт работающих профилей.
//!
//! # Где живут данные во время работы
//!
//! Движок получает `--user-data-dir` на **расшифрованную** копию профиля в
//! `vault/tmp/<uuid>/`. Пока браузер работает, открытые данные существуют на
//! диске — это осознанное свойство версии v1 (см. `docs/THREAT-MODEL.md`):
//! без шифрованной файловой системы открытый текст неизбежен. Лаунчер
//! сокращает это окно: данные шифруются сразу после закрытия окна браузера.
//!
//! # Кто следит за завершением
//!
//! `std::process::Child` нельзя «ждать» без блокировки, а лаунчер не должен
//! замораживать интерфейс. Поэтому менеджер опрашивает процессы (`try_wait`)
//! по таймеру и возвращает завершившиеся: вызывающий код шифрует их данные
//! обратно и обновляет журнал.
//!
//! # Остановка
//!
//! Сначала вежливая просьба закрыться (на Windows — `taskkill /T` без `/F`,
//! то есть `WM_CLOSE` окнам; на Linux — `SIGTERM` группе процессов), затем
//! ожидание, затем принудительное завершение дерева процессов. Только после
//! этого данные шифруются: убивать браузер раньше нельзя, иначе он не успеет
//! сбросить свои файлы на диск.

pub mod branding;
pub mod discovery;
pub mod flags;
pub mod journal;
pub mod startpage;

use std::collections::HashMap;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicIsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use serde::Serialize;

use crate::vault::{Result, VaultError};

use discovery::Engine;
use flags::LaunchPlan;
use journal::Entry;

/// Сколько ждать вежливого закрытия до принудительного завершения.
pub const GRACEFUL_TIMEOUT: Duration = Duration::from_secs(12);

/// Шаг опроса процессов.
pub const POLL_STEP: Duration = Duration::from_millis(200);

/// Работающий движок (внутреннее представление с процессом).
struct RunningInstance {
    profile_id: String,
    pid: u32,
    temp_dir: PathBuf,
    engine_version: String,
    started_unix: u64,
    child: Child,
    /// Описатель главного окна: через него окно закрывается вежливо.
    window: Arc<AtomicIsize>,
}

impl RunningInstance {
    /// Пытается узнать, завершился ли процесс, не блокируясь.
    fn exited(&mut self) -> bool {
        matches!(self.child.try_wait(), Ok(Some(_)))
    }

    fn view(&self) -> RunningView {
        RunningView {
            profile_id: self.profile_id.clone(),
            pid: self.pid,
            engine_version: self.engine_version.clone(),
            started_unix: self.started_unix,
            temp_dir: self.temp_dir.to_string_lossy().to_string(),
        }
    }
}

/// Результат запуска: описание для интерфейса и ячейка описателя окна.
pub struct Launched {
    pub view: RunningView,
    pub window: Arc<AtomicIsize>,
}

/// Сведения о работающем профиле: то, что видит интерфейс и журнал.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct RunningView {
    pub profile_id: String,
    pub pid: u32,
    pub engine_version: String,
    pub started_unix: u64,
    pub temp_dir: String,
}

impl RunningView {
    /// Запись журнала для этого запуска.
    pub fn journal_entry(&self, state: &str) -> Entry {
        Entry {
            profile_id: self.profile_id.clone(),
            pid: self.pid,
            temp_dir: self.temp_dir.clone(),
            state: state.to_string(),
            engine_version: self.engine_version.clone(),
            started_unix: self.started_unix,
        }
    }
}

/// Учёт работающих движков.
#[derive(Default)]
pub struct EngineManager {
    running: Mutex<HashMap<String, RunningInstance>>,
}

impl EngineManager {
    /// Запускает движок и берёт процесс под учёт.
    ///
    /// Возвращает описание запуска и ячейку с описателем окна: её заполняет
    /// слежение за оформлением, а читает остановка профиля.
    pub fn launch(
        &self,
        engine: &Engine,
        plan: &LaunchPlan,
        profile_id: &str,
        temp_dir: PathBuf,
    ) -> Result<Launched> {
        if self.is_running(profile_id) {
            return Err(VaultError::AlreadyRunning(profile_id.to_string()));
        }

        let child = spawn(engine, plan)?;
        let window = Arc::new(AtomicIsize::new(0));
        let instance = RunningInstance {
            profile_id: profile_id.to_string(),
            pid: child.id(),
            temp_dir,
            engine_version: engine.version.clone(),
            started_unix: crate::vault::unix_now(),
            child,
            window: Arc::clone(&window),
        };

        let mut guard = self.lock();
        // Между проверкой и вставкой мог вклиниться другой запуск: второй
        // процесс придётся завершить, иначе он останется без учёта.
        if guard.contains_key(profile_id) {
            let pid = instance.pid;
            drop(guard);
            let _ = force_kill(pid);
            return Err(VaultError::AlreadyRunning(profile_id.to_string()));
        }
        let view = instance.view();
        guard.insert(profile_id.to_string(), instance);
        Ok(Launched { view, window })
    }

    /// Идентификаторы работающих профилей.
    pub fn ids(&self) -> Vec<String> {
        let guard = self.lock();
        let mut ids: Vec<String> = guard.keys().cloned().collect();
        ids.sort();
        ids
    }

    /// Сведения для интерфейса.
    pub fn views(&self) -> Vec<RunningView> {
        let guard = self.lock();
        let mut views: Vec<RunningView> = guard.values().map(RunningInstance::view).collect();
        views.sort_by(|left, right| left.profile_id.cmp(&right.profile_id));
        views
    }

    /// Работает ли профиль.
    pub fn is_running(&self, profile_id: &str) -> bool {
        self.lock().contains_key(profile_id)
    }

    /// Просит движок закрыться (вежливо).
    pub fn request_close(&self, profile_id: &str) -> Result<()> {
        let (pid, window) = {
            let guard = self.lock();
            let instance = guard
                .get(profile_id)
                .ok_or_else(|| VaultError::NotRunning(profile_id.to_string()))?;
            (instance.pid, instance.window.load(Ordering::SeqCst))
        };
        graceful_close(pid, window)
    }

    /// Забирает из учёта завершившиеся процессы.
    pub fn reap(&self) -> Vec<RunningView> {
        let mut guard = self.lock();
        let finished: Vec<String> = guard
            .iter_mut()
            .filter_map(|(id, instance)| {
                if instance.exited() {
                    Some(id.clone())
                } else {
                    None
                }
            })
            .collect();

        finished
            .into_iter()
            .filter_map(|id| guard.remove(&id).map(|instance| instance.view()))
            .collect()
    }

    /// Забирает из учёта профиль, если его процесс уже завершился.
    pub fn take_if_exited(&self, profile_id: &str) -> Option<RunningView> {
        let mut guard = self.lock();
        let exited = guard
            .get_mut(profile_id)
            .map(RunningInstance::exited)
            .unwrap_or(false);
        if exited {
            guard.remove(profile_id).map(|instance| instance.view())
        } else {
            None
        }
    }

    /// Ждёт завершения профиля не дольше указанного времени.
    pub fn wait_exit(&self, profile_id: &str, timeout: Duration) -> Option<RunningView> {
        let deadline = Instant::now() + timeout;
        loop {
            if let Some(view) = self.take_if_exited(profile_id) {
                return Some(view);
            }
            if Instant::now() >= deadline {
                return None;
            }
            std::thread::sleep(POLL_STEP);
        }
    }

    /// Завершает процесс принудительно.
    pub fn kill(&self, profile_id: &str) -> Result<()> {
        let pid = {
            let guard = self.lock();
            guard
                .get(profile_id)
                .ok_or_else(|| VaultError::NotRunning(profile_id.to_string()))?
                .pid
        };
        force_kill(pid)
    }

    /// Полная остановка одного профиля: вежливо, затем принудительно.
    ///
    /// Возвращает описание остановленного запуска либо `None`, если профиль
    /// не был под учётом.
    pub fn stop(
        &self,
        profile_id: &str,
        graceful: Duration,
        forced: Duration,
    ) -> Option<RunningView> {
        let mut view = self.take_if_exited(profile_id);
        if view.is_some() {
            return view;
        }
        if !self.is_running(profile_id) {
            return None;
        }

        let _ = self.request_close(profile_id);
        view = self.wait_exit(profile_id, graceful);
        if view.is_some() {
            return view;
        }

        let _ = self.kill(profile_id);
        view = self.wait_exit(profile_id, forced);
        if view.is_some() {
            return view;
        }

        // Процесс не отвечает даже на принудительное завершение: убираем его
        // из учёта, чтобы лаунчер не считал профиль работающим вечно.
        self.remove(profile_id)
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, HashMap<String, RunningInstance>> {
        self.running
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    /// Убирает профиль из учёта, не дожидаясь процесса бесконечно.
    ///
    /// `Child::wait` без ограничения мог бы подвесить команду остановки
    /// навсегда, а интерфейс — остаться в состоянии «останавливаю…».
    pub fn remove(&self, profile_id: &str) -> Option<RunningView> {
        let mut guard = self.lock();
        let mut instance = guard.remove(profile_id)?;
        let deadline = Instant::now() + Duration::from_secs(2);
        loop {
            match instance.child.try_wait() {
                Ok(Some(_)) => break,
                Ok(None) if Instant::now() < deadline => std::thread::sleep(POLL_STEP),
                _ => {
                    // Последняя попытка: завершаем сам процесс и не ждём.
                    let _ = instance.child.kill();
                    let _ = instance.child.try_wait();
                    break;
                }
            }
        }
        Some(instance.view())
    }
}

/// Запускает процесс движка с планом.
fn spawn(engine: &Engine, plan: &LaunchPlan) -> Result<Child> {
    let mut command = Command::new(&engine.program);
    command
        .args(&plan.args)
        .current_dir(&engine.root)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());

    // Отдельная группа процессов: при остановке сигнал уходит всему дереву,
    // а не только главному процессу.
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        command.process_group(0);
    }

    command
        .spawn()
        .map_err(|error| VaultError::EngineFailed(format!("{}: {error}", engine.program.display())))
}

/// Вежливая просьба закрыться.
///
/// На Windows `taskkill` без `/F` окно **не** закрывает: движок на такой
/// сигнал не реагирует (проверено на живом процессе). Поэтому основное
/// действие — `WM_CLOSE` главному окну, то есть ровно то, что делает
/// пользователь, нажимая крестик. Дерево процессов при этом тоже получает
/// вежливый сигнал: так закрываются уже готовые к выходу вспомогательные
/// процессы движка.
fn graceful_close(pid: u32, window: isize) -> Result<()> {
    #[cfg(windows)]
    {
        let mut asked = false;
        if window != 0 && branding::close_window(window) {
            asked = true;
        }

        let status = Command::new("taskkill")
            .args(["/PID", &pid.to_string(), "/T"])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();

        if asked {
            return Ok(());
        }
        match status {
            Ok(_) => Ok(()),
            Err(error) => Err(VaultError::EngineFailed(format!(
                "не удалось попросить процесс {pid} закрыться: {error}"
            ))),
        }
    }

    #[cfg(not(windows))]
    {
        let _ = window;
        // Отрицательный идентификатор — вся группа процессов.
        let group = format!("-{pid}");
        let status = Command::new("kill")
            .args(["-TERM", &group])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
        if matches!(status, Ok(code) if code.success()) {
            return Ok(());
        }
        let status = Command::new("kill")
            .args(["-TERM", &pid.to_string()])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
        match status {
            Ok(_) => Ok(()),
            Err(error) => Err(VaultError::EngineFailed(format!(
                "не удалось попросить процесс {pid} закрыться: {error}"
            ))),
        }
    }
}

/// Принудительное завершение дерева процессов.
fn force_kill(pid: u32) -> Result<()> {
    #[cfg(windows)]
    {
        let status = Command::new("taskkill")
            .args(["/PID", &pid.to_string(), "/T", "/F"])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
        match status {
            Ok(_) => Ok(()),
            Err(error) => Err(VaultError::EngineFailed(format!(
                "не удалось завершить процесс {pid}: {error}"
            ))),
        }
    }

    #[cfg(not(windows))]
    {
        let group = format!("-{pid}");
        let status = Command::new("kill").args(["-KILL", &group]).status();
        if matches!(status, Ok(code) if code.success()) {
            return Ok(());
        }
        let status = Command::new("kill")
            .args(["-KILL", &pid.to_string()])
            .status();
        match status {
            Ok(_) => Ok(()),
            Err(error) => Err(VaultError::EngineFailed(format!(
                "не удалось завершить процесс {pid}: {error}"
            ))),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vault::metadata::ProfileKind;

    /// Долгоживущая команда для проверки жизненного цикла.
    fn sleeper(kind: ProfileKind) -> (Engine, LaunchPlan) {
        #[cfg(windows)]
        let (program, args) = (
            "cmd".to_string(),
            vec!["/C".to_string(), "ping -n 60 127.0.0.1 > NUL".to_string()],
        );
        #[cfg(not(windows))]
        let (program, args) = ("sleep".to_string(), vec!["60".to_string()]);

        let engine = Engine {
            kind,
            version: "test".to_string(),
            program: PathBuf::from(&program),
            root: std::env::temp_dir(),
        };
        let plan = LaunchPlan {
            args,
            user_data_dir: std::env::temp_dir().to_string_lossy().to_string(),
            proxy: None,
        };
        (engine, plan)
    }

    /// Короткоживущая команда: завершается сама.
    fn quick() -> (Engine, LaunchPlan) {
        #[cfg(windows)]
        let (program, args) = (
            "cmd".to_string(),
            vec!["/C".to_string(), "exit 0".to_string()],
        );
        #[cfg(not(windows))]
        let (program, args) = ("true".to_string(), Vec::<String>::new());

        let engine = Engine {
            kind: ProfileKind::Normal,
            version: "test".to_string(),
            program: PathBuf::from(program),
            root: std::env::temp_dir(),
        };
        let plan = LaunchPlan {
            args,
            user_data_dir: std::env::temp_dir().to_string_lossy().to_string(),
            proxy: None,
        };
        (engine, plan)
    }

    #[test]
    fn launch_registers_the_profile_and_refuses_a_duplicate() {
        let (engine, plan) = sleeper(ProfileKind::Normal);
        let manager = EngineManager::default();
        let temp = std::env::temp_dir();

        if manager
            .launch(&engine, &plan, "profile-1", temp.clone())
            .is_err()
        {
            // В ограниченном окружении запуск процессов может быть запрещён.
            return;
        }

        assert!(manager.is_running("profile-1"));
        assert!(matches!(
            manager.launch(&engine, &plan, "profile-1", temp),
            Err(VaultError::AlreadyRunning(_))
        ));
        assert_eq!(manager.ids(), vec!["profile-1".to_string()]);
        assert_eq!(manager.views().len(), 1);
        assert!(manager.views()[0].pid > 0);

        let stopped = manager.stop(
            "profile-1",
            Duration::from_secs(10),
            Duration::from_secs(10),
        );
        assert!(stopped.is_some(), "профиль должен остановиться");
        assert!(!manager.is_running("profile-1"));
    }

    #[test]
    fn operations_on_unknown_profile_are_errors() {
        let manager = EngineManager::default();
        assert!(matches!(
            manager.request_close("нет-такого"),
            Err(VaultError::NotRunning(_))
        ));
        assert!(matches!(
            manager.kill("нет-такого"),
            Err(VaultError::NotRunning(_))
        ));
        assert!(!manager.is_running("нет-такого"));
        assert!(manager
            .stop(
                "нет-такого",
                Duration::from_millis(10),
                Duration::from_millis(10)
            )
            .is_none());
    }

    #[test]
    fn reap_returns_finished_processes_only() {
        let (engine, plan) = quick();
        let manager = EngineManager::default();

        if manager
            .launch(&engine, &plan, "fast", std::env::temp_dir())
            .is_err()
        {
            return;
        }

        let deadline = Instant::now() + Duration::from_secs(10);
        let mut reaped = Vec::new();
        while reaped.is_empty() && Instant::now() < deadline {
            std::thread::sleep(POLL_STEP);
            reaped = manager.reap();
        }

        assert_eq!(reaped.len(), 1);
        assert_eq!(reaped[0].profile_id, "fast");
        assert!(manager.ids().is_empty());
    }

    /// Диагностика на живом браузере: сколько занимает каждый шаг остановки.
    ///
    /// Запускается вручную:
    /// `cargo test --lib manual_stop_timing -- --ignored --nocapture`
    #[test]
    #[ignore]
    fn manual_stop_timing() {
        use crate::vault::metadata::ProfileKind;
        use crate::vault::session::Vault;

        let Some(program) = chromium_for_diagnostics() else {
            eprintln!("браузер для диагностики не найден — тест пропущен");
            return;
        };

        let started = Instant::now();
        let tmp = tempfile::tempdir().unwrap();
        let mut vault = Vault::create_with_params(
            tmp.path(),
            "diagnostic-password",
            crate::vault::KdfParams {
                algorithm: "argon2id".to_string(),
                m_cost_kib: 64,
                t_cost: 1,
                p_cost: 1,
            },
        )
        .unwrap();
        let id = vault
            .create_profile("Диагностика", ProfileKind::Normal, None, None)
            .unwrap()
            .id;
        let plain = vault.temp_profile_dir(&id);
        vault.unseal_profile(&id, &plain).unwrap();
        eprintln!("[{:?}] хранилище и профиль готовы", started.elapsed());

        let engine = Engine {
            kind: ProfileKind::Normal,
            version: "diagnostic".to_string(),
            program: program.clone(),
            root: program.parent().unwrap().to_path_buf(),
        };
        let plan = LaunchPlan {
            args: vec![
                format!("--user-data-dir={}", plain.display()),
                "--no-first-run".to_string(),
                "--no-default-browser-check".to_string(),
            ],
            user_data_dir: plain.to_string_lossy().to_string(),
            proxy: None,
        };

        let manager = EngineManager::default();
        let launched = manager
            .launch(&engine, &plan, &id, plain.clone())
            .expect("движок должен запуститься");
        eprintln!(
            "[{:?}] движок запущен, pid {}",
            started.elapsed(),
            launched.view.pid
        );

        crate::engine::branding::start(
            launched.view.pid,
            "Диагностика".to_string(),
            "chrome".to_string(),
            Arc::clone(&launched.window),
        );
        std::thread::sleep(Duration::from_secs(6));
        let window = launched.window.load(Ordering::SeqCst);
        eprintln!("[{:?}] окно: {window}", started.elapsed());

        let close_started = Instant::now();
        let result = manager.request_close(&id);
        eprintln!(
            "[{:?}] вежливое закрытие вернулось за {:?}: {result:?}",
            started.elapsed(),
            close_started.elapsed()
        );

        let wait_started = Instant::now();
        let stopped = manager.wait_exit(&id, Duration::from_secs(12));
        eprintln!(
            "[{:?}] ожидание закрытия: {:?}, успех: {}",
            started.elapsed(),
            wait_started.elapsed(),
            stopped.is_some()
        );

        if stopped.is_none() {
            let kill_started = Instant::now();
            let _ = manager.kill(&id);
            eprintln!(
                "[{:?}] принудительное завершение вернулось за {:?}",
                started.elapsed(),
                kill_started.elapsed()
            );
            let killed = manager.wait_exit(&id, Duration::from_secs(8));
            eprintln!("[{:?}] после kill: {}", started.elapsed(), killed.is_some());
        }

        let seal_started = Instant::now();
        let _ = manager.remove(&id);
        match vault.plaintext_state(&id) {
            Ok(state) => {
                let sealed = vault.seal_profile(&id, &plain);
                eprintln!(
                    "[{:?}] шифрование вернулось за {:?}: {:?} (состояние до: {state:?})",
                    started.elapsed(),
                    seal_started.elapsed(),
                    sealed.map(|stats| stats.entries)
                );
            }
            Err(error) => eprintln!("состояние не прочитано: {error}"),
        }

        let wipe_started = Instant::now();
        let _ = vault.discard_plaintext(&id);
        eprintln!(
            "[{:?}] затирание копии вернулось за {:?}",
            started.elapsed(),
            wipe_started.elapsed()
        );
    }

    /// Путь к браузеру для диагностики: переменная окружения или известные пути.
    fn chromium_for_diagnostics() -> Option<PathBuf> {
        if let Ok(value) = std::env::var("FOUSBROWSER_ENGINE_PATH") {
            let path = PathBuf::from(value);
            if path.is_file() {
                return Some(path);
            }
        }
        let candidates = [
            r"C:\Program Files\Google\Chrome\Application\chrome.exe",
            r"C:\Program Files (x86)\Google\Chrome\Application\chrome.exe",
            "/usr/bin/chromium",
            "/usr/bin/google-chrome",
        ];
        candidates
            .iter()
            .map(PathBuf::from)
            .find(|path| path.is_file())
    }

    #[test]
    fn journal_entry_from_view_has_no_secrets() {
        let (engine, plan) = sleeper(ProfileKind::Antidetect);
        let manager = EngineManager::default();
        if manager
            .launch(&engine, &plan, "profile-2", std::env::temp_dir())
            .is_err()
        {
            return;
        }

        let view = manager.views().remove(0);
        let entry = view.journal_entry(journal::STATE_RUNNING);
        let text = serde_json::to_string(&entry).unwrap();
        assert!(text.contains("profile-2"));
        assert_eq!(entry.pid, view.pid);
        for forbidden in ["secret", "password", "seed"] {
            assert!(!text.contains(forbidden));
        }

        let _ = manager.stop(
            "profile-2",
            Duration::from_secs(10),
            Duration::from_secs(10),
        );
    }
}
