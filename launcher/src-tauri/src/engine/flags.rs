//! Флаги командной строки для запуска движка.
//!
//! # Normal
//!
//! Стоковый Chromium: только изоляция данных (`--user-data-dir`), отключение
//! первого запуска и проверок по умолчанию. Ничего, что меняло бы поведение
//! браузера как такового.
//!
//! # Antidetect
//!
//! Те же базовые флаги плюс подмена отпечатка. Значения **детерминированы
//! зерном профиля**: один и тот же профиль всегда выглядит одинаково, а два
//! разных профиля — по-разному. Это важно: если отпечаток менялся бы при
//! каждом запуске, профиль выглядел бы как новый браузер каждый раз.
//!
//! Флаги соответствуют сборке fingerprint-chromium (Фаза A плана движка):
//! `--fingerprint`, `--fingerprint-platform`, `--fingerprint-brand`,
//! `--fingerprint-hardware-concurrency`, `--timezone`,
//! `--disable-non-proxied-udp`. Свои патчи (Фаза B) добавят остальное.
//!
//! # Клонирование
//!
//! Клон получает новое зерно, поэтому его отпечаток отличается от исходного —
//! при совпадающих настройках и прокси.

use std::path::Path;

use crate::vault::metadata::{ProfileKind, ProfileMeta, ProxyConfig, ProxyScheme};

/// Заголовок окна профиля: единственное имя, которое должен видеть человек.
pub fn window_title(profile_name: &str) -> String {
    format!("FousBrowser — {profile_name}")
}

/// Варианты платформы для подмены отпечатка.
const PLATFORMS: [&str; 3] = ["windows", "linux", "macos"];

/// Варианты бренда браузера.
const BRANDS: [&str; 5] = ["Chrome", "Chromium", "Edge", "Brave", "Opera"];

/// Варианты числа логических ядер.
const CORES: [u32; 4] = [4, 8, 12, 16];

/// Часовые пояса, которые не выбиваются из общей картины.
const TIMEZONES: [&str; 6] = [
    "Europe/Berlin",
    "Europe/Amsterdam",
    "Europe/Warsaw",
    "America/New_York",
    "Asia/Singapore",
    "UTC",
];

/// Готовый план запуска.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LaunchPlan {
    pub args: Vec<String>,
    /// Каталог данных браузера — вынесен отдельно: он же проверяется в тестах.
    pub user_data_dir: String,
    /// Прокси, который реально пойдёт в командную строку (без пароля).
    pub proxy: Option<String>,
}

/// Строит план запуска.
///
/// `proxy_address` — адрес, который можно показать в командной строке:
/// либо сам прокси (если он без аутентификации), либо локальный мост.
/// `newtab_extension` supplies our permission-free new-tab page.
pub fn build(
    profile: &ProfileMeta,
    temp_dir: &Path,
    proxy_address: Option<&str>,
    newtab_extension: Option<&Path>,
) -> LaunchPlan {
    let user_data_dir = temp_dir.to_string_lossy().to_string();

    let mut args = vec![
        format!("--user-data-dir={user_data_dir}"),
        "--no-first-run".to_string(),
        "--no-default-browser-check".to_string(),
        "--no-service-autorun".to_string(),
        // Окно «браузер был закрыт неправильно» не должно появляться после
        // штатной остановки профиля лаунчером.
        "--disable-session-crashed-bubble".to_string(),
        // Лаунчер сам шифрует данные: автоматические отчёты не нужны.
        "--disable-breakpad".to_string(),
        // Chrome for Testing explicitly supports this switch.
        "--disable-infobars".to_string(),
    ];

    if profile.kind == ProfileKind::Antidetect {
        args.extend(fingerprint_args(profile.seed));
    }

    if let Some(address) = proxy_address {
        args.push(format!("--proxy-server={address}"));
        args.push("--disable-quic".to_string());
        args.push("--force-webrtc-ip-handling-policy=disable_non_proxied_udp".to_string());
    }

    if profile.restore_tabs {
        args.push("--restore-last-session".to_string());
    }
    if let Some(extension) = newtab_extension {
        args.push(format!("--load-extension={}", extension.display()));
        // On the first run Chromium may navigate before registering the new-tab
        // override. Open the same local page only when there is no saved session.
        if !super::startpage::has_saved_session(temp_dir) {
            args.push(super::startpage::file_url(&extension.join("index.html")));
        }
    }

    LaunchPlan {
        args,
        user_data_dir,
        proxy: proxy_address.map(str::to_string),
    }
}

/// Флаги подмены отпечатка по зерну профиля.
pub fn fingerprint_args(seed: u32) -> Vec<String> {
    let platform = PLATFORMS[index(seed, 1, PLATFORMS.len())];
    let brand = BRANDS[index(seed, 2, BRANDS.len())];
    let cores = CORES[index(seed, 3, CORES.len())];
    let timezone = TIMEZONES[index(seed, 4, TIMEZONES.len())];

    vec![
        format!("--fingerprint={seed}"),
        format!("--fingerprint-platform={platform}"),
        format!("--fingerprint-brand={brand}"),
        format!("--fingerprint-hardware-concurrency={cores}"),
        format!("--timezone={timezone}"),
        // Запрет UDP вне прокси: закрывает утечку настоящего адреса WebRTC.
        "--disable-non-proxied-udp".to_string(),
    ]
}

/// Адрес прокси для командной строки.
///
/// Пароль сюда не попадает никогда: он либо не задан, либо передаётся
/// локальному мосту по внутреннему каналу.
pub fn proxy_address(proxy: &ProxyConfig) -> String {
    let scheme = match proxy.scheme {
        ProxyScheme::Socks5 => "socks5",
        ProxyScheme::Http => "http",
        ProxyScheme::Https => "https",
    };
    let host = if proxy.host.contains(':') && !proxy.host.starts_with('[') {
        format!("[{}]", proxy.host)
    } else {
        proxy.host.clone()
    };
    format!("{scheme}://{host}:{}", proxy.port)
}

/// Есть ли у прокси учётные данные.
pub fn proxy_needs_bridge(proxy: &ProxyConfig) -> bool {
    proxy.username.is_some() || proxy.password.is_some()
}

/// Детерминированный выбор из списка по зерну.
///
/// Смешивание (xorshift-подобное) нужно, чтобы соседние зёрна давали разные
/// комбинации, а не соседние индексы.
fn index(seed: u32, salt: u32, modulo: usize) -> usize {
    let mut value = seed ^ salt.wrapping_mul(0x9E37_79B9);
    value ^= value >> 16;
    value = value.wrapping_mul(0x7feb_352d);
    value ^= value >> 15;
    value = value.wrapping_mul(0x846c_a68b);
    value ^= value >> 16;
    (value as usize) % modulo
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vault::metadata::ProfileMeta;

    fn profile(kind: ProfileKind, seed: u32) -> ProfileMeta {
        ProfileMeta {
            id: "11111111-2222-3333-4444-555555555555".to_string(),
            name: "Тест".to_string(),
            kind,
            seed,
            proxy: None,
            created_unix: 0,
            engine_version: None,
            restore_tabs: true,
            note: None,
        }
    }

    fn proxy(with_credentials: bool) -> ProxyConfig {
        ProxyConfig {
            scheme: ProxyScheme::Socks5,
            host: "gate.example".to_string(),
            port: 1080,
            username: with_credentials.then(|| "user".to_string()),
            password: with_credentials.then(|| "secret".to_string()),
        }
    }

    #[test]
    fn normal_launch_has_no_fingerprint_flags() {
        let plan = build(
            &profile(ProfileKind::Normal, 42),
            Path::new("/tmp/p"),
            None,
            None,
        );
        assert!(plan
            .args
            .iter()
            .any(|arg| arg.starts_with("--user-data-dir=")));
        assert!(!plan.args.iter().any(|arg| arg.starts_with("--fingerprint")));
        assert!(!plan.args.iter().any(|arg| arg.starts_with("--timezone")));
        assert_eq!(plan.proxy, None);
    }

    #[test]
    fn antidetect_launch_carries_consistent_fingerprint() {
        let plan = build(
            &profile(ProfileKind::Antidetect, 12345),
            Path::new("/tmp/p"),
            None,
            None,
        );
        assert!(plan.args.iter().any(|arg| arg == "--fingerprint=12345"));
        assert!(plan
            .args
            .iter()
            .any(|arg| arg.starts_with("--fingerprint-platform=")));
        assert!(plan
            .args
            .iter()
            .any(|arg| arg == "--disable-non-proxied-udp"));
    }

    #[test]
    fn fingerprint_is_deterministic_and_profile_specific() {
        let first = fingerprint_args(1000);
        let second = fingerprint_args(1000);
        assert_eq!(first, second, "один профиль — один отпечаток");

        let other = fingerprint_args(1001);
        assert_ne!(first, other, "разные зёрна дают разные отпечатки");
    }

    #[test]
    fn chosen_values_come_from_the_allowed_sets() {
        for seed in 0..200u32 {
            let args = fingerprint_args(seed);
            let value = |prefix: &str| {
                args.iter()
                    .find(|arg| arg.starts_with(prefix))
                    .unwrap()
                    .trim_start_matches(prefix)
                    .to_string()
            };
            assert!(PLATFORMS.contains(&value("--fingerprint-platform=").as_str()));
            assert!(BRANDS.contains(&value("--fingerprint-brand=").as_str()));
            assert!(TIMEZONES.contains(&value("--timezone=").as_str()));
            let cores: u32 = value("--fingerprint-hardware-concurrency=")
                .parse()
                .unwrap();
            assert!(CORES.contains(&cores));
        }
    }

    #[test]
    fn distribution_is_not_degenerate() {
        // Проверяем, что выбор не «залипает» на одном значении.
        let platforms: std::collections::HashSet<String> = (0..200u32)
            .map(|seed| {
                fingerprint_args(seed)
                    .into_iter()
                    .find(|arg| arg.starts_with("--fingerprint-platform="))
                    .unwrap()
            })
            .collect();
        assert!(
            platforms.len() >= 3,
            "платформа должна варьироваться: {platforms:?}"
        );
    }

    #[test]
    fn newtab_extension_does_not_append_a_tab_to_restored_sessions() {
        let temp = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(temp.path().join("Default/Sessions")).unwrap();
        std::fs::write(temp.path().join("Default/Sessions/Session_123"), b"saved").unwrap();
        let plan = build(
            &profile(ProfileKind::Normal, 5),
            temp.path(),
            None,
            Some(Path::new("C:/start")),
        );
        assert!(plan.args.contains(&"--load-extension=C:/start".into()));
        assert!(plan.args.contains(&"--restore-last-session".into()));
        assert!(plan.args.iter().all(|arg| arg.starts_with("--")));

        let without = build(
            &profile(ProfileKind::Normal, 5),
            Path::new("/tmp/p"),
            None,
            None,
        );
        assert!(
            !without.args.iter().any(|arg| arg.contains("file://")),
            "без стартовой страницы лишних аргументов быть не должно"
        );
    }

    #[test]
    fn first_run_opens_our_page_without_touching_preferences() {
        let temp = tempfile::tempdir().unwrap();
        let plan = build(
            &profile(ProfileKind::Antidetect, 5),
            temp.path(),
            None,
            Some(Path::new("/start")),
        );
        assert_eq!(
            plan.args.last(),
            Some(&super::super::startpage::file_url(Path::new(
                "/start/index.html"
            )))
        );
        assert!(!temp.path().join("Default/Preferences").exists());
    }

    #[test]
    fn restoration_can_be_disabled_without_disabling_newtab() {
        let mut p = profile(ProfileKind::Antidetect, 5);
        p.restore_tabs = false;
        let plan = build(&p, Path::new("/tmp/p"), None, Some(Path::new("/start")));
        assert!(!plan.args.contains(&"--restore-last-session".into()));
        assert!(plan.args.contains(&"--load-extension=/start".into()));
        assert!(plan.args.contains(&"--disable-infobars".into()));
    }

    #[test]
    fn window_is_presented_as_fousbrowser() {
        let plan = build(
            &profile(ProfileKind::Normal, 7),
            Path::new("/tmp/p"),
            None,
            None,
        );
        assert_eq!(window_title("Рабочий"), "FousBrowser — Рабочий");
        for arg in &plan.args {
            let lowered = arg.to_lowercase();
            for vendor in ["edge", "msedge", "yandex", "opera"] {
                assert!(
                    !lowered.contains(vendor),
                    "в командной строке не должно быть чужого бренда: {arg}"
                );
            }
        }
    }

    #[test]
    fn proxy_address_never_contains_credentials() {
        let address = proxy_address(&proxy(true));
        assert_eq!(address, "socks5://gate.example:1080");
        assert!(!address.contains("secret"));
        assert!(!address.contains("user"));

        let plan = build(
            &profile(ProfileKind::Normal, 1),
            Path::new("/tmp/p"),
            Some(&address),
            None,
        );
        assert!(plan
            .args
            .iter()
            .any(|arg| arg == "--proxy-server=socks5://gate.example:1080"));
        assert!(!plan.args.iter().any(|arg| arg.contains("secret")));
    }

    #[test]
    fn bridge_is_required_only_for_authenticated_proxies() {
        assert!(!proxy_needs_bridge(&proxy(false)));
        assert!(proxy_needs_bridge(&proxy(true)));
    }
}
