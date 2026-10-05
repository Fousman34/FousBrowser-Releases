//! Загрузка обновлений: прогресс, контрольные суммы, staging.
//!
//! Загрузка идёт во **временный** каталог: работающая версия движка не
//! трогается до тех пор, пока файл не проверен целиком. Это важно для
//! отмены и для сбоя сети — в обоих случаях текущий движок остаётся целым.

use std::collections::HashMap;
use std::fs;
use std::io::{Read, Write};
use std::path::Path;
use std::time::Duration;

use sha2::{Digest, Sha256};

use super::{UpdateError, UpdateResult};

/// Сколько ждать соединения, а сколько — данных.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(30);
const READ_TIMEOUT: Duration = Duration::from_secs(60);
const USER_AGENT: &str = concat!("FousBrowser/", env!("CARGO_PKG_VERSION"));

fn request_error(url: &str, error: ureq::Error) -> UpdateError {
    match error {
        ureq::Error::Status(code @ (404 | 410), _) => {
            UpdateError::Source(format!("файл не найден в источнике (HTTP {code}): {url}"))
        }
        ureq::Error::Status(403, response)
            if response.header("X-RateLimit-Remaining") == Some("0") =>
        {
            UpdateError::Network(
                "GitHub временно ограничил число запросов с этого IP-адреса".into(),
            )
        }
        other => UpdateError::Network(format!("{url}: {other}")),
    }
}

/// Сколько раз пробовать докачать файл.
///
/// Загрузка движка — это сотни мегабайт с чужого сервера: соединение рвётся,
/// CDN притормаживает, машина уходит в сон. Поэтому обрыв не считается
/// окончательной ошибкой: файл докачивается с того места, где остановился.
/// Это не теория: без докачки загрузка 185 МиБ обрывалась на 15 МиБ.
pub const MAX_ATTEMPTS: usize = 6;

/// Ход загрузки.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Progress {
    pub received: u64,
    /// Полный размер, если источник его сообщил.
    pub total: Option<u64>,
}

impl Progress {
    /// Процент выполнения, если известен полный размер.
    pub fn percent(&self) -> Option<f64> {
        match self.total {
            Some(total) if total > 0 => {
                Some((self.received as f64 / total as f64 * 100.0).clamp(0.0, 100.0))
            }
            _ => None,
        }
    }
}

/// Контрольная сумма SHA-256 в шестнадцатеричном виде.
pub fn sha256_hex(data: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hex::encode(hasher.finalize())
}

/// Контрольная сумма файла.
pub fn sha256_file(path: &Path) -> UpdateResult<String> {
    let mut file = fs::File::open(path)?;
    let mut hasher = Sha256::new();
    let mut buffer = vec![0u8; 64 * 1024];
    loop {
        let read = file.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    Ok(hex::encode(hasher.finalize()))
}

/// Разбирает список контрольных сумм вида `sha256sum`.
///
/// Понимает и `хеш  имя`, и `хеш *имя` (пометка двоичного режима), пропускает
/// пустые строки и комментарии, снимает CRLF.
pub fn parse_sums(text: &str) -> HashMap<String, String> {
    let mut result = HashMap::new();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        // Формат: хеш, пробел(ы), необязательная звёздочка, имя файла.
        let mut parts = line.split_whitespace();
        let (Some(hash), Some(name)) = (parts.next(), parts.next()) else {
            continue;
        };
        if hash.len() != 64 || !hash.chars().all(|character| character.is_ascii_hexdigit()) {
            continue;
        }
        let name = name.trim_start_matches('*');
        result.insert(name.to_string(), hash.to_lowercase());
    }
    result
}

/// Ожидаемая сумма для файла из списка.
pub fn expected_hash(sums: &str, asset_name: &str) -> Option<String> {
    parse_sums(sums).remove(asset_name)
}

/// Сверяет файл со списком контрольных сумм.
pub fn verify_file(sums: &str, asset_name: &str, path: &Path) -> UpdateResult<()> {
    let expected = expected_hash(sums, asset_name).ok_or_else(|| {
        UpdateError::Insecure(format!("в списке контрольных сумм нет файла {asset_name}"))
    })?;
    let actual = sha256_file(path)?;
    if actual != expected {
        return Err(UpdateError::Insecure(format!(
            "контрольная сумма файла {asset_name} не совпала: ожидалась {expected}, получена {actual}"
        )));
    }
    Ok(())
}

/// Загружает файл по ссылке, сообщая о ходе загрузки.
///
/// Обрыв соединения не считается окончательной ошибкой: файл докачивается с
/// того места, где остановился (заголовок `Range`), до [`MAX_ATTEMPTS`] попыток.
/// Возвращает число байт, оказавшихся в файле.
pub fn download(
    url: &str,
    target: &Path,
    mut on_progress: impl FnMut(Progress),
) -> UpdateResult<u64> {
    let mut attempt = 1;
    loop {
        match download_once(url, target, &mut on_progress) {
            Ok(bytes) => return Ok(bytes),
            Err(error) => {
                if attempt >= MAX_ATTEMPTS || !is_retryable(&error) {
                    return Err(error);
                }
                // Небольшая пауза перед следующей попыткой: если сервер
                // притормозил, мгновенный повтор только повторит обрыв.
                std::thread::sleep(Duration::from_secs(2 * attempt as u64));
                attempt += 1;
            }
        }
    }
}

/// Обрыв сети или ввод-вывод имеет смысл повторить; отказ проверки — нет.
fn is_retryable(error: &UpdateError) -> bool {
    matches!(error, UpdateError::Network(_) | UpdateError::Io(_))
}

/// Одна попытка загрузки: при наличии части файла запрашивает остаток.
fn download_once(
    url: &str,
    target: &Path,
    on_progress: &mut impl FnMut(Progress),
) -> UpdateResult<u64> {
    if let Some(parent) = target.parent() {
        crate::paths::ensure_dir(parent)?;
    }

    // Отдельные пределы для соединения и чтения: общий предел на весь запрос
    // обрывал бы большую загрузку на середине (так и случилось на 185 МиБ).
    let agent = ureq::AgentBuilder::new()
        .user_agent(USER_AGENT)
        .timeout_connect(CONNECT_TIMEOUT)
        .timeout_read(READ_TIMEOUT)
        .build();

    let already = fs::metadata(target).map(|meta| meta.len()).unwrap_or(0);
    let mut request = agent.get(url).set("Cache-Control", "no-cache");
    if already > 0 {
        request = request.set("Range", &format!("bytes={already}-"));
    }

    let response = request.call().map_err(|error| request_error(url, error))?;
    let status = response.status();

    // 206 — сервер согласился отдать остаток; 200 — отдаёт файл целиком,
    // поэтому начинаем заново, иначе получим дубликат в начале.
    let (mut file, mut received) = match (already, status) {
        (0, 200) => (fs::File::create(target)?, 0u64),
        (already, 206) => (fs::OpenOptions::new().append(true).open(target)?, already),
        (already, 416) => {
            // Файл уже скачан полностью.
            return Ok(already);
        }
        (_, 200) => (fs::File::create(target)?, 0u64),
        (_, status) => {
            return Err(UpdateError::Network(format!(
                "{url}: неожиданный ответ {status}"
            )))
        }
    };

    // При ответе 206 длина относится к остатку, а не ко всему файлу.
    let remaining = response
        .header("Content-Length")
        .and_then(|value| value.parse::<u64>().ok());
    let total = remaining.map(|length| received + length);

    let mut reader = response.into_reader();
    let mut buffer = vec![0u8; 64 * 1024];
    loop {
        let read = match reader.read(&mut buffer) {
            Ok(0) => break,
            Ok(read) => read,
            Err(error) => {
                // Уже полученные байты не теряем: следующая попытка продолжит.
                file.sync_all()?;
                return Err(UpdateError::Io(error));
            }
        };
        file.write_all(&buffer[..read])?;
        received += read as u64;
        on_progress(Progress { received, total });
    }
    file.sync_all()?;

    Ok(received)
}

/// Загружает небольшой текстовый файл (манифест, список сумм, подпись).
pub fn fetch_text(url: &str) -> UpdateResult<String> {
    let response = ureq::get(url)
        .set("User-Agent", USER_AGENT)
        .set("Cache-Control", "no-cache")
        .timeout(READ_TIMEOUT)
        .call()
        .map_err(|error| request_error(url, error))?;
    response
        .into_string()
        .map_err(|error| UpdateError::Network(format!("{url}: {error}")))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::TcpListener;

    #[test]
    fn sha256_matches_known_value() {
        // Общеизвестное значение для строки "abc".
        assert_eq!(
            sha256_hex(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        let tmp = tempfile::tempdir().unwrap();
        let file = tmp.path().join("data.bin");
        fs::write(&file, b"abc").unwrap();
        assert_eq!(sha256_file(&file).unwrap(), sha256_hex(b"abc"));
    }

    #[test]
    fn sums_parsing_accepts_real_formats() {
        let archive_hash = sha256_hex(b"antidetect-win64.zip");
        let sums_hash = sha256_hex(b"SHA256SUMS");
        let text = format!(
            "{archive_hash}  antidetect-win64.zip\r\n\
             {sums_hash} *SHA256SUMS\n\
             \n\
             # комментарий\n\
             мусор без суммы\n"
        );

        let sums = parse_sums(&text);
        assert_eq!(
            sums.get("antidetect-win64.zip").map(String::as_str),
            Some(archive_hash.as_str())
        );
        // Звёздочка (двоичный режим) не должна попадать в имя файла.
        assert!(sums.contains_key("SHA256SUMS"));
        assert!(!sums.contains_key("*SHA256SUMS"));
        assert_eq!(sums.len(), 2);
    }

    #[test]
    fn verification_detects_modified_file() {
        let tmp = tempfile::tempdir().unwrap();
        let file = tmp.path().join("asset.zip");
        fs::write(&file, b"original").unwrap();
        let sums = format!("{}  asset.zip\n", sha256_hex(b"original"));

        verify_file(&sums, "asset.zip", &file).expect("совпадающая сумма принимается");

        fs::write(&file, "подменённый файл".as_bytes()).unwrap();
        let error = verify_file(&sums, "asset.zip", &file).unwrap_err();
        assert!(matches!(error, UpdateError::Insecure(_)), "{error}");
        assert!(error.to_string().contains("не совпала"));
    }

    #[test]
    fn verification_refuses_files_missing_from_the_list() {
        let tmp = tempfile::tempdir().unwrap();
        let file = tmp.path().join("asset.zip");
        fs::write(&file, "данные".as_bytes()).unwrap();
        let error = verify_file("", "asset.zip", &file).unwrap_err();
        assert!(error.to_string().contains("нет файла"), "{error}");
    }

    #[test]
    fn progress_percent_is_safe() {
        assert_eq!(
            Progress {
                received: 0,
                total: None
            }
            .percent(),
            None
        );
        assert_eq!(
            Progress {
                received: 0,
                total: Some(0)
            }
            .percent(),
            None
        );
        assert_eq!(
            Progress {
                received: 50,
                total: Some(200)
            }
            .percent(),
            Some(25.0)
        );
        // Больше заявленного быть не может: значение ограничивается сотней.
        assert_eq!(
            Progress {
                received: 500,
                total: Some(200)
            }
            .percent(),
            Some(100.0)
        );
    }

    /// Простейший HTTP-сервер на один запрос: проверяем загрузку без сети.
    fn serve_once(body: Vec<u8>) -> (String, std::thread::JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let handle = std::thread::spawn(move || {
            if let Ok((mut socket, _)) = listener.accept() {
                let mut request = [0u8; 1024];
                let _ = socket.read(&mut request);
                let headers = format!(
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    body.len()
                );
                let _ = socket.write_all(headers.as_bytes());
                let _ = socket.write_all(&body);
                let _ = socket.flush();
            }
        });
        (format!("http://{address}/asset"), handle)
    }

    #[test]
    fn download_saves_file_and_reports_progress() {
        let body: Vec<u8> = (0..200_000u32).map(|value| (value % 251) as u8).collect();
        let (url, server) = serve_once(body.clone());

        let tmp = tempfile::tempdir().unwrap();
        let target = tmp.path().join("nested").join("asset.zip");
        let mut updates = Vec::new();

        let received = download(&url, &target, |progress| updates.push(progress)).unwrap();
        server.join().unwrap();

        assert_eq!(received, body.len() as u64);
        assert_eq!(fs::read(&target).unwrap(), body);
        assert!(
            updates.len() >= 2,
            "прогресс должен сообщаться по ходу загрузки"
        );
        assert_eq!(updates.last().unwrap().total, Some(body.len() as u64));
        assert_eq!(updates.last().unwrap().percent(), Some(100.0));
        assert_eq!(sha256_file(&target).unwrap(), sha256_hex(&body));
    }

    #[test]
    fn missing_file_is_reported_without_retrying_a_permanent_404() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://{}/missing", listener.local_addr().unwrap());
        let server = std::thread::spawn(move || {
            let (mut socket, _) = listener.accept().unwrap();
            let mut buffer = [0; 2048];
            let read = socket.read(&mut buffer).unwrap();
            assert!(read > 0);
            socket
                .write_all(
                    b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                )
                .unwrap();
        });
        let tmp = tempfile::tempdir().unwrap();
        let error = download(&url, &tmp.path().join("file.zip"), |_| {}).unwrap_err();
        assert!(matches!(error, UpdateError::Source(_)));
        assert!(error.to_string().contains("404"));
        server.join().unwrap();
    }

    /// Сервер, который на первом запросе отдаёт половину файла и закрывает
    /// соединение, а на втором — остаток по заголовку `Range`.
    fn serve_with_break(body: Vec<u8>) -> (String, std::thread::JoinHandle<u32>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let handle = std::thread::spawn(move || {
            let mut requests = 0u32;
            let half = body.len() / 2;
            for _ in 0..2 {
                let Ok((mut socket, _)) = listener.accept() else {
                    break;
                };
                let mut buffer = vec![0u8; 4096];
                let read = socket.read(&mut buffer).unwrap_or(0);
                let request = String::from_utf8_lossy(&buffer[..read]).to_lowercase();
                requests += 1;

                if let Some(rest) = request.split("range: bytes=").nth(1) {
                    let from = rest
                        .split('-')
                        .next()
                        .unwrap_or("0")
                        .trim()
                        .parse::<usize>()
                        .unwrap_or(0);
                    let from = from.min(body.len());
                    let tail = &body[from..];
                    let headers = format!(
                        "HTTP/1.1 206 Partial Content\r\nContent-Length: {}\r\nContent-Range: bytes {}-{}/{}\r\nConnection: close\r\n\r\n",
                        tail.len(),
                        from,
                        body.len().saturating_sub(1),
                        body.len()
                    );
                    let _ = socket.write_all(headers.as_bytes());
                    let _ = socket.write_all(tail);
                } else {
                    let headers = format!(
                        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                        body.len()
                    );
                    let _ = socket.write_all(headers.as_bytes());
                    // Отдаём половину и закрываем соединение: так выглядит
                    // обрыв на медленном канале.
                    let _ = socket.write_all(&body[..half]);
                }
                let _ = socket.flush();
            }
            requests
        });
        (format!("http://{address}/asset"), handle)
    }

    #[test]
    fn download_resumes_after_a_broken_connection() {
        let body: Vec<u8> = (0..300_000u32).map(|value| (value % 253) as u8).collect();
        let (url, server) = serve_with_break(body.clone());

        let tmp = tempfile::tempdir().unwrap();
        let target = tmp.path().join("asset.zip");
        let mut updates = Vec::new();

        let received = download(&url, &target, |progress| updates.push(progress)).unwrap();
        let requests = server.join().unwrap();

        assert_eq!(
            requests, 2,
            "ожидались две попытки: обрыв и докачка остатка"
        );
        assert_eq!(received, body.len() as u64);
        assert_eq!(
            fs::read(&target).unwrap(),
            body,
            "после докачки файл обязан совпасть целиком"
        );
        assert_eq!(
            updates.last().unwrap().percent(),
            Some(100.0),
            "прогресс должен дойти до конца"
        );
    }

    #[test]
    fn download_reports_network_failure() {
        // Порт, на котором никто не слушает.
        let error = download(
            "http://127.0.0.1:1/asset",
            Path::new("/tmp/нет-такого-каталога/asset"),
            |_| {},
        )
        .unwrap_err();
        assert!(matches!(error, UpdateError::Network(_)), "{error}");
    }
}
