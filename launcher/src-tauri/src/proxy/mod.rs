//! Локальный прокси-мост.
//!
//! # Зачем он нужен
//!
//! Движки не умеют парольную аутентификацию прокси через `--proxy-server`:
//! флаг принимает только адрес. Поэтому лаунчер поднимает на `127.0.0.1`
//! собственный SOCKS5-сервер, который **знает** логин и пароль апстрима, а
//! движку отдаётся уже «беспарольный» локальный адрес.
//!
//! Что это даёт:
//!
//! - пароль прокси не попадает ни в командную строку процесса, ни в журналы:
//!   в `--proxy-server` уходит только `socks5://127.0.0.1:<порт>`;
//! - аутентификация выполняется там, где она поддерживается;
//! - видно, куда именно идёт трафик профиля (мост живёт в процессе лаунчера);
//! - не нужны внешние бинарники вроде `gost`.
//!
//! # Что поддерживается
//!
//! Апстрим: **SOCKS5** (в том числе с логином и паролем, RFC 1929) и
//! **HTTP CONNECT** (`Proxy-Authorization: Basic`). Схема `https` пока
//! дозванивается тем же `HTTP CONNECT`, но без TLS до прокси: это отмечено
//! в `docs/ARCHITECTURE.md` как известное ограничение, а не спрятано.
//!
//! # Границы
//!
//! Мост слушает только петлевой адрес (`127.0.0.1`) и случайный порт: снаружи
//! он недоступен, а порт не виден заранее. Мост живёт ровно столько, сколько
//! работает профиль.

use std::collections::HashMap;
use std::io;
use std::sync::Mutex;
use std::time::Duration;

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine as _;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::oneshot;

use crate::vault::metadata::{ProxyConfig, ProxyScheme};
use crate::vault::{Result, VaultError};

/// Сколько ждать установления соединения с апстримом.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(15);

/// Верхняя граница заголовков ответа HTTP-прокси.
const MAX_HTTP_HEADERS: usize = 16 * 1024;

const SOCKS_VERSION: u8 = 0x05;
const SOCKS_NO_AUTH: u8 = 0x00;
const SOCKS_USER_PASS: u8 = 0x02;
const SOCKS_NO_ACCEPTABLE: u8 = 0xFF;
const SOCKS_CMD_CONNECT: u8 = 0x01;
const SOCKS_ATYP_IPV4: u8 = 0x01;
const SOCKS_ATYP_DOMAIN: u8 = 0x03;
const SOCKS_ATYP_IPV6: u8 = 0x04;
const SOCKS_REP_SUCCEEDED: u8 = 0x00;
const SOCKS_REP_NOT_ALLOWED: u8 = 0x07;

/// Работающий мост.
pub struct Bridge {
    port: u16,
    shutdown: Option<oneshot::Sender<()>>,
    relay: tokio::task::JoinHandle<()>,
}

impl Bridge {
    /// Поднимает мост к указанному прокси.
    pub async fn start(upstream: ProxyConfig) -> Result<Self> {
        let listener = TcpListener::bind(("127.0.0.1", 0)).await.map_err(|error| {
            VaultError::EngineFailed(format!("не удалось занять порт для прокси-моста: {error}"))
        })?;
        let port = listener
            .local_addr()
            .map_err(|error| VaultError::EngineFailed(error.to_string()))?
            .port();

        let (shutdown, mut stopped) = oneshot::channel::<()>();
        let relay = tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = &mut stopped => break,
                    accepted = listener.accept() => {
                        match accepted {
                            Ok((stream, _)) => {
                                let upstream = upstream.clone();
                                tokio::spawn(async move {
                                    // Ошибка одного соединения не должна ронять мост.
                                    let _ = serve(stream, upstream).await;
                                });
                            }
                            Err(_) => break,
                        }
                    }
                }
            }
        });

        Ok(Self {
            port,
            shutdown: Some(shutdown),
            relay,
        })
    }

    /// Порт, на котором слушает мост.
    pub fn port(&self) -> u16 {
        self.port
    }

    /// Адрес для `--proxy-server`: без логина и пароля.
    pub fn address(&self) -> String {
        format!("socks5://127.0.0.1:{}", self.port)
    }

    /// Останавливает мост.
    pub fn stop(mut self) {
        if let Some(shutdown) = self.shutdown.take() {
            let _ = shutdown.send(());
        }
        self.relay.abort();
    }
}

impl Drop for Bridge {
    fn drop(&mut self) {
        if let Some(shutdown) = self.shutdown.take() {
            let _ = shutdown.send(());
        }
        self.relay.abort();
    }
}

/// Учёт мостов по профилям.
#[derive(Default)]
pub struct BridgeManager {
    bridges: Mutex<HashMap<String, Bridge>>,
}

impl BridgeManager {
    /// Ставит мост профилю, заменяя прежний.
    pub fn insert(&self, profile_id: &str, bridge: Bridge) {
        let mut guard = self.lock();
        if let Some(previous) = guard.remove(profile_id) {
            previous.stop();
        }
        guard.insert(profile_id.to_string(), bridge);
    }

    /// Порт моста профиля, если он поднят.
    pub fn port(&self, profile_id: &str) -> Option<u16> {
        self.lock().get(profile_id).map(Bridge::port)
    }

    /// Останавливает мост профиля.
    pub fn stop(&self, profile_id: &str) {
        let bridge = self.lock().remove(profile_id);
        if let Some(bridge) = bridge {
            bridge.stop();
        }
    }

    /// Останавливает все мосты.
    pub fn stop_all(&self) {
        let bridges: Vec<Bridge> = {
            let mut guard = self.lock();
            guard.drain().map(|(_, bridge)| bridge).collect()
        };
        for bridge in bridges {
            bridge.stop();
        }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, HashMap<String, Bridge>> {
        self.bridges
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }
}

/// Цель соединения, запрошенная движком.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Target {
    atyp: u8,
    address: Vec<u8>,
    port: u16,
}

impl Target {
    /// Представление `host:port` для HTTP CONNECT.
    fn authority(&self) -> String {
        let host = match self.atyp {
            SOCKS_ATYP_IPV4 => self
                .address
                .chunks(1)
                .map(|byte| byte[0].to_string())
                .collect::<Vec<_>>()
                .join("."),
            SOCKS_ATYP_IPV6 => {
                let groups: Vec<String> = self
                    .address
                    .chunks(2)
                    .map(|pair| format!("{:02x}{:02x}", pair[0], pair[1]))
                    .collect();
                format!("[{}]", groups.join(":"))
            }
            _ => String::from_utf8_lossy(&self.address).to_string(),
        };
        format!("{host}:{}", self.port)
    }

    /// Запрос CONNECT в том виде, в каком его ждёт апстрим.
    ///
    /// Доменное имя в SOCKS5 кодируется **с байтом длины** перед собой
    /// (ATYP=3). Если его потерять, апстрим прочитает первый символ имени
    /// как длину и будет ждать данные, которых не будет.
    fn connect_request(&self) -> Vec<u8> {
        let mut request = Vec::with_capacity(7 + self.address.len());
        request.extend_from_slice(&[SOCKS_VERSION, SOCKS_CMD_CONNECT, 0x00, self.atyp]);
        if self.atyp == SOCKS_ATYP_DOMAIN {
            request.push(self.address.len() as u8);
        }
        request.extend_from_slice(&self.address);
        request.extend_from_slice(&self.port.to_be_bytes());
        request
    }
}

/// Обслуживает одно соединение движка.
async fn serve(mut client: TcpStream, upstream: ProxyConfig) -> io::Result<()> {
    let target = match socks5_handshake(&mut client).await {
        Ok(target) => target,
        Err(error) => {
            // Отказ клиенту отправляет сама `socks5_handshake`, здесь важно
            // только закрыть соединение.
            let _ = client.shutdown().await;
            return Err(error);
        }
    };

    let mut remote = match connect_upstream(&upstream, &target).await {
        Ok(stream) => stream,
        Err(error) => {
            let _ = client
                .write_all(&[
                    SOCKS_VERSION,
                    SOCKS_REP_NOT_ALLOWED,
                    0x00,
                    SOCKS_ATYP_IPV4,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                ])
                .await;
            let _ = client.shutdown().await;
            return Err(error);
        }
    };

    client
        .write_all(&[
            SOCKS_VERSION,
            SOCKS_REP_SUCCEEDED,
            0x00,
            SOCKS_ATYP_IPV4,
            0,
            0,
            0,
            0,
            0,
            0,
        ])
        .await?;
    tokio::io::copy_bidirectional(&mut client, &mut remote).await?;
    Ok(())
}

/// Принимает приветствие SOCKS5 и запрос CONNECT.
async fn socks5_handshake(client: &mut TcpStream) -> io::Result<Target> {
    let mut greeting = [0u8; 2];
    client.read_exact(&mut greeting).await?;
    if greeting[0] != SOCKS_VERSION {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "движок обратился не по протоколу SOCKS5",
        ));
    }

    let mut methods = vec![0u8; greeting[1] as usize];
    client.read_exact(&mut methods).await?;
    if !methods.contains(&SOCKS_NO_AUTH) {
        let _ = client
            .write_all(&[SOCKS_VERSION, SOCKS_NO_ACCEPTABLE])
            .await;
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "движок не предложил метод без аутентификации",
        ));
    }
    // Мост доступен только с петлевого адреса, поэтому внутри лаунчера
    // аутентификация не нужна: секрет остаётся в апстриме.
    client.write_all(&[SOCKS_VERSION, SOCKS_NO_AUTH]).await?;

    let mut request = [0u8; 4];
    client.read_exact(&mut request).await?;
    if request[0] != SOCKS_VERSION || request[1] != SOCKS_CMD_CONNECT {
        let _ = client
            .write_all(&[
                SOCKS_VERSION,
                SOCKS_REP_NOT_ALLOWED,
                0x00,
                SOCKS_ATYP_IPV4,
                0,
                0,
                0,
                0,
                0,
                0,
            ])
            .await;
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "поддерживается только команда CONNECT",
        ));
    }

    let address = match request[3] {
        SOCKS_ATYP_IPV4 => {
            let mut buffer = vec![0u8; 4];
            client.read_exact(&mut buffer).await?;
            buffer
        }
        SOCKS_ATYP_DOMAIN => {
            let mut length = [0u8; 1];
            client.read_exact(&mut length).await?;
            let mut buffer = vec![0u8; length[0] as usize];
            client.read_exact(&mut buffer).await?;
            buffer
        }
        SOCKS_ATYP_IPV6 => {
            let mut buffer = vec![0u8; 16];
            client.read_exact(&mut buffer).await?;
            buffer
        }
        other => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("неизвестный тип адреса: {other}"),
            ))
        }
    };

    let mut port = [0u8; 2];
    client.read_exact(&mut port).await?;
    Ok(Target {
        atyp: request[3],
        address,
        port: u16::from_be_bytes(port),
    })
}

/// Устанавливает соединение с апстримом через нужный протокол.
async fn connect_upstream(upstream: &ProxyConfig, target: &Target) -> io::Result<TcpStream> {
    let connect = async {
        match upstream.scheme {
            ProxyScheme::Socks5 => socks5_upstream(upstream, target).await,
            // Схема `https` пока обслуживается тем же HTTP CONNECT: TLS до
            // самого прокси не поднимается, это известное ограничение.
            ProxyScheme::Http | ProxyScheme::Https => http_connect_upstream(upstream, target).await,
        }
    };

    match tokio::time::timeout(CONNECT_TIMEOUT, connect).await {
        Ok(result) => result,
        Err(_) => Err(io::Error::new(
            io::ErrorKind::TimedOut,
            "прокси не ответил вовремя",
        )),
    }
}

/// Подключение через SOCKS5-апстрим, при необходимости с логином и паролем.
async fn socks5_upstream(upstream: &ProxyConfig, target: &Target) -> io::Result<TcpStream> {
    let mut stream = TcpStream::connect((upstream.host.as_str(), upstream.port)).await?;

    let with_credentials = upstream.username.is_some();
    let methods: &[u8] = if with_credentials {
        &[SOCKS_VERSION, 0x01, SOCKS_USER_PASS]
    } else {
        &[SOCKS_VERSION, 0x01, SOCKS_NO_AUTH]
    };
    stream.write_all(methods).await?;

    let mut choice = [0u8; 2];
    stream.read_exact(&mut choice).await?;
    if choice[0] != SOCKS_VERSION {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "прокси отвечает не по протоколу SOCKS5",
        ));
    }

    match choice[1] {
        SOCKS_NO_AUTH => {}
        SOCKS_USER_PASS => {
            let username = upstream.username.clone().unwrap_or_default();
            let password = upstream.password.clone().unwrap_or_default();
            if username.len() > 255 || password.len() > 255 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "логин или пароль прокси длиннее 255 байт",
                ));
            }
            let mut auth = Vec::with_capacity(3 + username.len() + password.len());
            auth.push(0x01);
            auth.push(username.len() as u8);
            auth.extend_from_slice(username.as_bytes());
            auth.push(password.len() as u8);
            auth.extend_from_slice(password.as_bytes());
            stream.write_all(&auth).await?;

            let mut answer = [0u8; 2];
            stream.read_exact(&mut answer).await?;
            if answer[1] != 0x00 {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "прокси отклонил логин или пароль",
                ));
            }
        }
        other => {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                format!("прокси требует неподдерживаемый метод аутентификации: {other:#04x}"),
            ))
        }
    }

    let request = target.connect_request();
    stream.write_all(&request).await?;

    let mut reply = [0u8; 4];
    stream.read_exact(&mut reply).await?;
    if reply[1] != SOCKS_REP_SUCCEEDED {
        return Err(io::Error::new(
            io::ErrorKind::ConnectionRefused,
            format!("прокси отказал в соединении, код {:#04x}", reply[1]),
        ));
    }

    // Ответ содержит адрес, который нужно пропустить.
    let skip = match reply[3] {
        SOCKS_ATYP_IPV4 => 4,
        SOCKS_ATYP_IPV6 => 16,
        SOCKS_ATYP_DOMAIN => {
            let mut length = [0u8; 1];
            stream.read_exact(&mut length).await?;
            length[0] as usize
        }
        other => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("неизвестный тип адреса в ответе прокси: {other}"),
            ))
        }
    };
    let mut skipped = vec![0u8; skip + 2];
    stream.read_exact(&mut skipped).await?;

    Ok(stream)
}

/// Подключение через HTTP-прокси методом CONNECT.
async fn http_connect_upstream(upstream: &ProxyConfig, target: &Target) -> io::Result<TcpStream> {
    let mut stream = TcpStream::connect((upstream.host.as_str(), upstream.port)).await?;
    let authority = target.authority();

    let mut request = format!("CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\n");
    if let (Some(username), Some(password)) = (&upstream.username, &upstream.password) {
        let token = B64.encode(format!("{username}:{password}"));
        request.push_str(&format!("Proxy-Authorization: Basic {token}\r\n"));
    }
    request.push_str("Proxy-Connection: keep-alive\r\n\r\n");
    stream.write_all(request.as_bytes()).await?;

    let mut headers = Vec::with_capacity(256);
    let mut byte = [0u8; 1];
    loop {
        stream.read_exact(&mut byte).await?;
        headers.push(byte[0]);
        if headers.ends_with(b"\r\n\r\n") {
            break;
        }
        if headers.len() > MAX_HTTP_HEADERS {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "прокси вернул слишком длинный ответ",
            ));
        }
    }

    let text = String::from_utf8_lossy(&headers);
    let status = text.lines().next().unwrap_or_default();
    if !status.contains(" 200") {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!("прокси отказал: {}", status.trim()),
        ));
    }

    Ok(stream)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn upstream(host: &str, port: u16, with_credentials: bool) -> ProxyConfig {
        ProxyConfig {
            scheme: ProxyScheme::Socks5,
            host: host.to_string(),
            port,
            username: with_credentials.then(|| "user".to_string()),
            password: with_credentials.then(|| "secret".to_string()),
        }
    }

    /// Поднимает эхо-сервер и возвращает его адрес.
    async fn echo_server() -> std::net::SocketAddr {
        let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
        let address = listener.local_addr().unwrap();
        tokio::spawn(async move {
            while let Ok((mut stream, _)) = listener.accept().await {
                tokio::spawn(async move {
                    let mut buffer = [0u8; 512];
                    if let Ok(read) = stream.read(&mut buffer).await {
                        let _ = stream.write_all(&buffer[..read]).await;
                    }
                });
            }
        });
        address
    }

    /// Клиент моста: проходит SOCKS5 и возвращает открытый поток.
    async fn socks5_client(port: u16, target: &str, target_port: u16) -> TcpStream {
        let mut stream = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
        stream
            .write_all(&[SOCKS_VERSION, 0x01, SOCKS_NO_AUTH])
            .await
            .unwrap();
        let mut choice = [0u8; 2];
        stream.read_exact(&mut choice).await.unwrap();
        assert_eq!(choice, [SOCKS_VERSION, SOCKS_NO_AUTH]);

        let mut request = vec![SOCKS_VERSION, SOCKS_CMD_CONNECT, 0x00, SOCKS_ATYP_DOMAIN];
        request.push(target.len() as u8);
        request.extend_from_slice(target.as_bytes());
        request.extend_from_slice(&target_port.to_be_bytes());
        stream.write_all(&request).await.unwrap();

        let mut reply = [0u8; 10];
        stream.read_exact(&mut reply).await.unwrap();
        assert_eq!(
            reply[1], SOCKS_REP_SUCCEEDED,
            "мост обязан подтвердить соединение"
        );
        stream
    }

    #[tokio::test]
    async fn bridge_relays_through_socks5_upstream_with_credentials() {
        // Апстрим: проверяет логин и пароль, затем проксирует на эхо-сервер.
        let echo = echo_server().await;
        let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
        let upstream_port = listener.local_addr().unwrap().port();

        let checker = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut greeting = [0u8; 3];
            stream.read_exact(&mut greeting).await.unwrap();
            assert_eq!(greeting, [SOCKS_VERSION, 0x01, SOCKS_USER_PASS]);
            stream
                .write_all(&[SOCKS_VERSION, SOCKS_USER_PASS])
                .await
                .unwrap();

            let mut head = [0u8; 2];
            stream.read_exact(&mut head).await.unwrap();
            assert_eq!(head[0], 0x01);
            let mut user = vec![0u8; head[1] as usize];
            stream.read_exact(&mut user).await.unwrap();
            let mut length = [0u8; 1];
            stream.read_exact(&mut length).await.unwrap();
            let mut password = vec![0u8; length[0] as usize];
            stream.read_exact(&mut password).await.unwrap();
            assert_eq!(user, b"user");
            assert_eq!(password, b"secret");
            stream.write_all(&[0x01, 0x00]).await.unwrap();

            let mut request = [0u8; 4];
            stream.read_exact(&mut request).await.unwrap();
            assert_eq!(request[1], SOCKS_CMD_CONNECT);
            let mut name_length = [0u8; 1];
            stream.read_exact(&mut name_length).await.unwrap();
            let mut name = vec![0u8; name_length[0] as usize];
            stream.read_exact(&mut name).await.unwrap();
            assert_eq!(name, b"example.test");
            let mut port = [0u8; 2];
            stream.read_exact(&mut port).await.unwrap();
            assert_eq!(u16::from_be_bytes(port), 443);

            stream
                .write_all(&[
                    SOCKS_VERSION,
                    SOCKS_REP_SUCCEEDED,
                    0x00,
                    SOCKS_ATYP_IPV4,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                ])
                .await
                .unwrap();

            // Дальше апстрим просто повторяет то, что пришло от клиента.
            let mut buffer = [0u8; 64];
            let read = stream.read(&mut buffer).await.unwrap();
            stream.write_all(&buffer[..read]).await.unwrap();
            let _ = echo;
        });

        let bridge = Bridge::start(upstream("127.0.0.1", upstream_port, true))
            .await
            .unwrap();
        let mut client = socks5_client(bridge.port(), "example.test", 443).await;
        client.write_all(b"ping").await.unwrap();
        let mut answer = [0u8; 4];
        client.read_exact(&mut answer).await.unwrap();
        assert_eq!(&answer, b"ping");

        checker.await.unwrap();
        bridge.stop();
    }

    #[tokio::test]
    async fn bridge_sends_basic_auth_to_http_upstream() {
        let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
        let upstream_port = listener.local_addr().unwrap().port();

        let checker = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut request = Vec::new();
            let mut byte = [0u8; 1];
            while !request.ends_with(b"\r\n\r\n") {
                stream.read_exact(&mut byte).await.unwrap();
                request.push(byte[0]);
            }
            let text = String::from_utf8_lossy(&request).to_string();
            assert!(
                text.starts_with("CONNECT example.test:8443 HTTP/1.1"),
                "{text}"
            );
            assert!(
                text.contains("Proxy-Authorization: Basic dXNlcjpzZWNyZXQ="),
                "логин и пароль обязаны уходить в заголовке: {text}"
            );
            stream
                .write_all(b"HTTP/1.1 200 Connection established\r\n\r\n")
                .await
                .unwrap();
            let mut buffer = [0u8; 64];
            let read = stream.read(&mut buffer).await.unwrap();
            stream.write_all(&buffer[..read]).await.unwrap();
        });

        let mut config = upstream("127.0.0.1", upstream_port, true);
        config.scheme = ProxyScheme::Http;

        let bridge = Bridge::start(config).await.unwrap();
        let mut client = socks5_client(bridge.port(), "example.test", 8443).await;
        client.write_all(b"ping").await.unwrap();
        let mut answer = [0u8; 4];
        client.read_exact(&mut answer).await.unwrap();
        assert_eq!(&answer, b"ping");

        checker.await.unwrap();
        bridge.stop();
    }

    #[tokio::test]
    async fn bridge_rejects_commands_other_than_connect() {
        let bridge = Bridge::start(upstream("127.0.0.1", 1, false))
            .await
            .unwrap();
        let mut client = TcpStream::connect(("127.0.0.1", bridge.port()))
            .await
            .unwrap();
        client
            .write_all(&[SOCKS_VERSION, 0x01, SOCKS_NO_AUTH])
            .await
            .unwrap();
        let mut choice = [0u8; 2];
        client.read_exact(&mut choice).await.unwrap();

        // 0x02 — BIND: мост его не поддерживает и обязан отказать.
        client
            .write_all(&[
                SOCKS_VERSION,
                0x02,
                0x00,
                SOCKS_ATYP_IPV4,
                127,
                0,
                0,
                1,
                0,
                80,
            ])
            .await
            .unwrap();
        let mut reply = [0u8; 10];
        client.read_exact(&mut reply).await.unwrap();
        assert_eq!(reply[1], SOCKS_REP_NOT_ALLOWED);
        bridge.stop();
    }

    #[tokio::test]
    async fn address_never_contains_credentials() {
        let bridge = Bridge::start(upstream("127.0.0.1", 1, true)).await.unwrap();
        let address = bridge.address();
        assert!(address.starts_with("socks5://127.0.0.1:"), "{address}");
        assert!(!address.contains("user"));
        assert!(!address.contains("secret"));
        bridge.stop();
    }

    #[tokio::test]
    async fn manager_stops_bridges_and_reports_port() {
        let manager = BridgeManager::default();
        let bridge = Bridge::start(upstream("127.0.0.1", 1, false))
            .await
            .unwrap();
        let port = bridge.port();
        manager.insert("profile-1", bridge);

        assert_eq!(manager.port("profile-1"), Some(port));
        manager.stop("profile-1");
        assert_eq!(manager.port("profile-1"), None);

        // Замена моста закрывает прежний.
        let first = Bridge::start(upstream("127.0.0.1", 1, false))
            .await
            .unwrap();
        let first_port = first.port();
        manager.insert("profile-2", first);
        let second = Bridge::start(upstream("127.0.0.1", 1, false))
            .await
            .unwrap();
        let second_port = second.port();
        manager.insert("profile-2", second);
        assert_eq!(manager.port("profile-2"), Some(second_port));
        assert_ne!(first_port, second_port);

        manager.stop_all();
        assert_eq!(manager.port("profile-2"), None);
    }

    #[tokio::test]
    async fn socks5_upstream_client_authenticates_and_connects() {
        // Прямая проверка клиента апстрима: если он не работает, мост
        // ответит движку отказом, и настоящая причина будет не видна.
        let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
        let port = listener.local_addr().unwrap().port();

        let checker = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut greeting = [0u8; 3];
            stream.read_exact(&mut greeting).await.unwrap();
            assert_eq!(greeting, [SOCKS_VERSION, 0x01, SOCKS_USER_PASS]);
            stream
                .write_all(&[SOCKS_VERSION, SOCKS_USER_PASS])
                .await
                .unwrap();

            let mut head = [0u8; 2];
            stream.read_exact(&mut head).await.unwrap();
            let mut user = vec![0u8; head[1] as usize];
            stream.read_exact(&mut user).await.unwrap();
            let mut length = [0u8; 1];
            stream.read_exact(&mut length).await.unwrap();
            let mut password = vec![0u8; length[0] as usize];
            stream.read_exact(&mut password).await.unwrap();
            assert_eq!(user, b"user");
            assert_eq!(password, b"secret");
            stream.write_all(&[0x01, 0x00]).await.unwrap();

            let mut request = [0u8; 4];
            stream.read_exact(&mut request).await.unwrap();
            let mut name_length = [0u8; 1];
            stream.read_exact(&mut name_length).await.unwrap();
            let mut name = vec![0u8; name_length[0] as usize];
            stream.read_exact(&mut name).await.unwrap();
            let mut port = [0u8; 2];
            stream.read_exact(&mut port).await.unwrap();
            assert_eq!(name, b"example.test");
            stream
                .write_all(&[
                    SOCKS_VERSION,
                    SOCKS_REP_SUCCEEDED,
                    0x00,
                    SOCKS_ATYP_IPV4,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                ])
                .await
                .unwrap();
        });

        let target = Target {
            atyp: SOCKS_ATYP_DOMAIN,
            address: b"example.test".to_vec(),
            port: 443,
        };
        let config = upstream("127.0.0.1", port, true);
        match socks5_upstream(&config, &target).await {
            Ok(_) => checker.await.unwrap(),
            Err(error) => panic!("клиент апстрима не смог подключиться: {error}"),
        }
    }

    #[test]
    fn connect_request_encodes_domain_length() {
        // Доменное имя обязано идти с байтом длины: без него апстрим
        // принимает первый символ имени за длину и ждёт данные вечно.
        let domain = Target {
            atyp: SOCKS_ATYP_DOMAIN,
            address: b"example.test".to_vec(),
            port: 443,
        };
        let request = domain.connect_request();
        assert_eq!(
            &request[..5],
            &[
                SOCKS_VERSION,
                SOCKS_CMD_CONNECT,
                0x00,
                SOCKS_ATYP_DOMAIN,
                12
            ]
        );
        assert_eq!(&request[5..17], b"example.test");
        assert_eq!(&request[17..], &443u16.to_be_bytes());
        assert_eq!(request.len(), 19);

        // У IP-адресов длины нет: она не нужна.
        let ipv4 = Target {
            atyp: SOCKS_ATYP_IPV4,
            address: vec![127, 0, 0, 1],
            port: 8080,
        };
        let request = ipv4.connect_request();
        assert_eq!(
            &request[..4],
            &[SOCKS_VERSION, SOCKS_CMD_CONNECT, 0x00, SOCKS_ATYP_IPV4]
        );
        assert_eq!(&request[4..8], &[127, 0, 0, 1]);
        assert_eq!(request.len(), 10);
    }

    #[test]
    fn target_authority_formats_addresses() {
        let ipv4 = Target {
            atyp: SOCKS_ATYP_IPV4,
            address: vec![93, 184, 216, 34],
            port: 443,
        };
        assert_eq!(ipv4.authority(), "93.184.216.34:443");

        let domain = Target {
            atyp: SOCKS_ATYP_DOMAIN,
            address: b"example.test".to_vec(),
            port: 8443,
        };
        assert_eq!(domain.authority(), "example.test:8443");

        let ipv6 = Target {
            atyp: SOCKS_ATYP_IPV6,
            address: vec![0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1],
            port: 80,
        };
        assert_eq!(
            ipv6.authority(),
            "[2001:0db8:0000:0000:0000:0000:0000:0001]:80"
        );
    }
}
