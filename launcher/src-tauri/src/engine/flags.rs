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

/// Имя класса окна (и связанное с ним представление профиля в системе).
pub const WINDOW_CLASS: &str = "FousBrowser";

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
/// `start_url` — наша стартовая страница: без неё движок открыл бы свою
/// страницу новой вкладки с чужим оформлением.
pub fn build(
    profile: &ProfileMeta,
    temp_dir: &Path,
    proxy_address: Option<&str>,
    start_url: Option<&str>,
) -> LaunchPlan {
    let user_data_dir = temp_dir.to_string_lossy().to_string();

    let mut args = vec![
        format!("--user-data-dir={user_data_dir}"),
        // Имя окна в системе — тоже часть оформления: в списке окон и на
        // панели задач профиль должен выглядеть как FousBrowser, а не как
        // чужой браузер. На Windows этот флаг игнорируется (там окно
        // оформляет сам лаунчер, см. `engine::branding`).
        format!("--class={WINDOW_CLASS}"),
        "--no-first-run".to_string(),
        "--no-default-browser-check".to_string(),
        "--no-service-autorun".to_string(),
        // Окно «браузер был закрыт неправильно» не должно появляться после
        // штатной остановки профиля лаунчером.
        "--disable-session-crashed-bubble".to_string(),
        // Лаунчер сам шифрует данные: автоматические отчёты не нужны.
        "--disable-breakpad".to_string(),
    ];

    if profile.kind == ProfileKind::Antidetect {
        args.extend(fingerprint_args(profile.seed));
    }

    if let Some(address) = proxy_address {
        args.push(format!("--proxy-server={address}"));
    }

    // Адрес страницы идёт последним аргументом без ключа: так движок
    // открывает её в первой вкладке вместо своей страницы новой вкладки.
    if let Some(url) = start_url {
        args.push(url.to_string());
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
    format!("{scheme}://{}:{}", proxy.host, proxy.port)
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
    fn start_page_is_the_last_positional_argument() {
        let plan = build(
            &profile(ProfileKind::Normal, 5),
            Path::new("/tmp/p"),
            None,
            Some("file:///C:/start/index.html"),
        );
        assert_eq!(
            plan.args.last().map(String::as_str),
            Some("file:///C:/start/index.html"),
            "страница открывается последним аргументом без ключа"
        );

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
    fn window_is_presented_as_fousbrowser() {
        let plan = build(
            &profile(ProfileKind::Normal, 7),
            Path::new("/tmp/p"),
            None,
            None,
        );
        assert!(
            plan.args.iter().any(|arg| arg == "--class=FousBrowser"),
            "имя окна задаётся классом FousBrowser"
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
