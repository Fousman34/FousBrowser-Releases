//! CryptoFS: шифрование данных профиля на диске.
//!
//! Пока браузер работает, данные профиля лежат расшифрованными во временном
//! каталоге. Всё остальное время на диске находится **контейнер**: дерево
//! каталогов профиля, в котором каждый файл заменён зашифрованным потоком.
//!
//! # Формат файла контейнера
//!
//! ```text
//! magic "FBX1" | version u8 | kind u8 | chunk_size u32 | plain_len u64
//! затем записи по 1 МиБ: nonce(24) || ciphertext || tag(16)
//! последняя запись — финальный маркер с пустым открытым текстом
//! ```
//!
//! `kind` различает обычный файл и символическую ссылку: цель ссылки
//! хранится как содержимое.
//!
//! # Что защищает AAD
//!
//! В AAD каждой записи входят: идентификатор хранилища и профиля, путь файла,
//! номер записи, полная длина файла, длина открытого текста записи, признак
//! последней записи и вид файла. Поэтому обнаруживаются:
//!
//! - перестановка и удаление записей (номер записи в AAD);
//! - перенос файла на другой путь (путь в AAD);
//! - перенос контейнера в другой профиль или другое хранилище (профиль в AAD
//!   и отдельный подключ на профиль);
//! - подмена заголовка: изменение длины файла или вида файла ломает проверку
//!   последней записи;
//! - обрезание файла: финальный маркер обязателен.
//!
//! # Что здесь не защищено
//!
//! Имена файлов и каталогов, их количество и приблизительные размеры видны:
//! шифруется содержимое, а не структура. Скрытие структуры требует
//! шифрованной файловой системы (FUSE/WinFsp) и отнесено к этапу v2 —
//! см. `docs/THREAT-MODEL.md`.
//!
//! # Почему подмена каталога делается через переименование
//!
//! Контейнер собирается целиком в `profiles/<uuid>.staging`, и только потом
//! подменяет рабочий каталог. Падение в любой момент оставляет либо прежний
//! контейнер, либо прежний и новый рядом, но никогда — полузаписанный.

use std::fs::{self, File};
use std::io::{BufReader, BufWriter, Read, Write};
use std::path::{Component, Path, PathBuf};

use zeroize::Zeroizing;

use super::crypto::{self, NONCE_LEN, TAG_LEN};
use super::error::{Result, VaultError};
use super::kdf::KEY_LEN;
use super::profiles::wipe_dir;
use super::session::UnlockedVault;
use crate::paths;

/// Сигнатура контейнера.
pub const MAGIC: [u8; 4] = *b"FBX1";

/// Версия формата контейнера.
pub const VERSION: u8 = 1;

/// Размер шифруемой записи (открытый текст).
pub const CHUNK_SIZE: usize = 1024 * 1024;

/// Верхняя граница размера записи, которую принимаем при чтении.
///
/// Заголовок не аутентифицирован сам по себе, поэтому «щедрый» размер записи
/// из повреждённого файла не должен приводить к выделению гигабайтов памяти.
const MAX_CHUNK_SIZE: usize = 16 * 1024 * 1024;

/// Длина заголовка контейнера.
pub const HEADER_LEN: usize = 4 + 1 + 1 + 4 + 8;

/// Вид записи: обычный файл.
pub const KIND_FILE: u8 = 0;

/// Вид записи: символическая ссылка.
pub const KIND_SYMLINK: u8 = 1;

/// Признак последней записи в AAD.
const FINAL_FLAG: u8 = 1;

/// Признак промежуточной записи в AAD.
const DATA_FLAG: u8 = 0;

/// Контекст AAD для файла контейнера.
const AAD_PREFIX: &[u8] = b"fousbrowser/v1/file";

/// Суффикс каталога, в котором собирается новый контейнер.
const STAGING_SUFFIX: &str = ".staging";

/// Суффикс каталога, в котором ждёт прежний контейнер.
const PREVIOUS_SUFFIX: &str = ".previous";

/// Что получилось в результате операции над контейнером.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct ContainerStats {
    /// Сколько файлов и ссылок перенесено.
    pub entries: usize,
    /// Сколько байт открытого текста.
    pub bytes: u64,
    /// Сколько файлов исчезло прямо во время шифрования.
    ///
    /// Браузер постоянно создаёт и удаляет служебные файлы, поэтому гонка
    /// при сборке контейнера — обычное дело: пропущенный файл к этому моменту
    /// уже удалён, и сохранять его содержимое не требуется.
    pub vanished: usize,
}

/// Итог проверки каталога на осиротевшие данные.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PlaintextState {
    /// Расшифрованной копии нет.
    Absent,
    /// Расшифрованная копия есть; указано число файлов и байт.
    Present { entries: usize, bytes: u64 },
}

impl UnlockedVault {
    /// Собирает контейнер профиля из расшифрованного каталога.
    ///
    /// Прежний контейнер сохраняется до момента успешной подмены: сбой на
    /// любом шаге не оставляет профиль без данных.
    pub fn seal_profile(&self, profile_id: &str, source: &Path) -> Result<ContainerStats> {
        if !source.is_dir() {
            return Err(VaultError::Invalid(format!(
                "расшифрованный каталог профиля не найден: {}",
                source.display()
            )));
        }

        // Ключ и AAD берутся до первой записи: если профиль неизвестен,
        // ошибка возвращается до любого изменения на диске.
        let key = self.profile_key(profile_id)?;
        let aad = self.profile_aad(profile_id);

        let target = self.profile_dir(profile_id);
        let parent = target
            .parent()
            .ok_or_else(|| VaultError::Invalid("у каталога профиля нет родителя".into()))?
            .to_path_buf();
        paths::ensure_dir(&parent)?;

        let staging = parent.join(format!("{profile_id}{STAGING_SUFFIX}"));
        let previous = parent.join(format!("{profile_id}{PREVIOUS_SUFFIX}"));
        wipe_dir(&staging)?;
        wipe_dir(&previous)?;
        paths::ensure_dir(&staging)?;

        let stats = match write_container(&key, &aad, source, &staging) {
            Ok(stats) => stats,
            Err(error) => {
                // Неудачная сборка не должна оставлять мусор рядом с профилем.
                let _ = wipe_dir(&staging);
                return Err(error);
            }
        };

        let target_existed = target.is_dir();
        if target_existed {
            fs::rename(&target, &previous)?;
        }
        if let Err(error) = fs::rename(&staging, &target) {
            // Возвращаем прежний контейнер на место.
            if target_existed {
                let _ = fs::rename(&previous, &target);
            }
            let _ = wipe_dir(&staging);
            return Err(error.into());
        }
        let _ = wipe_dir(&previous);

        Ok(stats)
    }

    /// Разворачивает контейнер профиля в расшифрованный каталог.
    ///
    /// Каталог назначения создаётся заново: смешение с прежним содержимым
    /// дало бы файлы, которых в контейнере нет.
    pub fn unseal_profile(&self, profile_id: &str, target: &Path) -> Result<ContainerStats> {
        let key = self.profile_key(profile_id)?;
        let aad = self.profile_aad(profile_id);

        wipe_dir(target)?;
        paths::ensure_dir(target)?;

        let container = self.profile_dir(profile_id);
        if !container.is_dir() {
            // Профиль без данных — это не ошибка: новый профиль пуст.
            return Ok(ContainerStats::default());
        }

        read_container(&key, &aad, &container, target)
    }

    /// Состояние расшифрованной копии профиля.
    pub fn plaintext_state(&self, profile_id: &str) -> Result<PlaintextState> {
        let dir = self.temp_profile_dir(profile_id);
        if !dir.is_dir() {
            return Ok(PlaintextState::Absent);
        }
        let (entries, bytes) = measure(&dir)?;
        if entries == 0 {
            return Ok(PlaintextState::Absent);
        }
        Ok(PlaintextState::Present { entries, bytes })
    }

    /// Стирает расшифрованную копию профиля.
    pub fn discard_plaintext(&self, profile_id: &str) -> Result<()> {
        wipe_dir(&self.temp_profile_dir(profile_id))
    }
}

/// Есть ли в каталоге зашифрованные данные профиля.
pub fn container_exists(dir: &Path) -> bool {
    dir.is_dir()
        && fs::read_dir(dir)
            .map(|mut it| it.next().is_some())
            .unwrap_or(false)
}

/// Сколько файлов и байт внутри дерева.
fn measure(root: &Path) -> Result<(usize, u64)> {
    let mut entries = 0usize;
    let mut bytes = 0u64;
    let mut stack = vec![root.to_path_buf()];

    while let Some(dir) = stack.pop() {
        let listing = match fs::read_dir(&dir) {
            Ok(listing) => listing,
            Err(error) if vanished(&error) => continue,
            Err(error) => return Err(error.into()),
        };
        for entry in listing {
            let entry = match entry {
                Ok(entry) => entry,
                Err(error) if vanished(&error) => continue,
                Err(error) => return Err(error.into()),
            };
            let file_type = match entry.file_type() {
                Ok(file_type) => file_type,
                Err(error) if vanished(&error) => continue,
                Err(error) => return Err(error.into()),
            };
            if file_type.is_dir() {
                stack.push(entry.path());
            } else if file_type.is_file() {
                // Размер тоже может исчезнуть вместе с файлом: подсчёт
                // не должен падать из-за служебных файлов браузера.
                match entry.metadata() {
                    Ok(metadata) => {
                        entries += 1;
                        bytes += metadata.len();
                    }
                    Err(error) if vanished(&error) => continue,
                    Err(error) => return Err(error.into()),
                }
            }
        }
    }
    Ok((entries, bytes))
}

/// Исчез ли файл или каталог прямо во время работы.
///
/// Браузер постоянно удаляет служебные файлы (метрики, кэш, временные
/// загрузки), поэтому «файл не найден» при сборке контейнера — не ошибка
/// данных: этого файла уже нет и сохранять нечего.
fn vanished(error: &std::io::Error) -> bool {
    error.kind() == std::io::ErrorKind::NotFound
}

/// То же для ошибки хранилища: нужно, чтобы отличать исчезнувший файл
/// от заблокированного (второй обязан остановить шифрование, иначе данные
/// будут потеряны).
fn is_vanished(error: &VaultError) -> bool {
    matches!(error, VaultError::Io(io) if vanished(io))
}

/// Собирает контейнер: обходит `source` и шифрует каждый файл.
fn write_container(
    key: &[u8; KEY_LEN],
    profile_aad: &[u8],
    source: &Path,
    staging: &Path,
) -> Result<ContainerStats> {
    let mut stats = ContainerStats::default();
    let mut stack = vec![(source.to_path_buf(), String::new())];

    while let Some((dir, prefix)) = stack.pop() {
        let listing = match fs::read_dir(&dir) {
            Ok(listing) => listing,
            Err(error) if vanished(&error) => continue,
            Err(error) => return Err(error.into()),
        };

        for entry in listing {
            let entry = match entry {
                Ok(entry) => entry,
                Err(error) if vanished(&error) => continue,
                Err(error) => return Err(error.into()),
            };
            let name = entry.file_name().to_string_lossy().to_string();
            let relative = if prefix.is_empty() {
                name
            } else {
                format!("{prefix}/{name}")
            };
            validate_relative(&relative)?;

            let path = entry.path();
            let file_type = match entry.file_type() {
                Ok(file_type) => file_type,
                Err(error) if vanished(&error) => continue,
                Err(error) => return Err(error.into()),
            };
            let destination = staging.join(&relative);

            if file_type.is_dir() {
                paths::ensure_dir(&destination)?;
                stack.push((path, relative));
                continue;
            }

            if file_type.is_symlink() {
                let target = match fs::read_link(&path) {
                    Ok(target) => target,
                    Err(error) if vanished(&error) => {
                        stats.vanished += 1;
                        continue;
                    }
                    Err(error) => return Err(error.into()),
                };
                let payload = target.to_string_lossy().into_owned().into_bytes();
                if let Some(parent) = destination.parent() {
                    paths::ensure_dir(parent)?;
                }
                store_entry(
                    key,
                    profile_aad,
                    &relative,
                    KIND_SYMLINK,
                    &payload,
                    &destination,
                )?;
                stats.entries += 1;
                stats.bytes += payload.len() as u64;
                continue;
            }

            if !file_type.is_file() {
                // Сокеты, каналы и устройства не переносим: в профиле браузера
                // их быть не может, а чтение такого файла может заблокироваться.
                continue;
            }

            if let Some(parent) = destination.parent() {
                paths::ensure_dir(parent)?;
            }
            match store_file(key, profile_aad, &relative, &path, &destination) {
                Ok(written) => {
                    stats.entries += 1;
                    stats.bytes += written;
                }
                // Файл исчез между обходом и чтением — сохранять нечего.
                Err(error) if is_vanished(&error) => stats.vanished += 1,
                // Всё остальное (например, файл занят другим процессом)
                // обязано остановить сборку: иначе данные потеряются молча.
                Err(error) => return Err(error),
            }
        }
    }

    Ok(stats)
}

/// Разворачивает контейнер: обходит зашифрованное дерево и пишет открытые файлы.
fn read_container(
    key: &[u8; KEY_LEN],
    profile_aad: &[u8],
    container: &Path,
    target: &Path,
) -> Result<ContainerStats> {
    let mut stats = ContainerStats::default();
    let mut stack = vec![(container.to_path_buf(), String::new())];

    while let Some((dir, prefix)) = stack.pop() {
        for entry in fs::read_dir(&dir)? {
            let entry = entry?;
            let name = entry.file_name().to_string_lossy().to_string();
            let relative = if prefix.is_empty() {
                name
            } else {
                format!("{prefix}/{name}")
            };
            // Имена в контейнере не аутентифицированы: путь с `..`,
            // абсолютный путь или префикс диска обязан быть отвергнут,
            // иначе распаковка вышла бы за пределы каталога профиля.
            validate_relative(&relative)?;

            let path = entry.path();
            let file_type = entry.file_type()?;
            let destination = target.join(&relative);

            if file_type.is_dir() {
                paths::ensure_dir(&destination)?;
                stack.push((path, relative));
                continue;
            }
            if !file_type.is_file() {
                continue;
            }

            if let Some(parent) = destination.parent() {
                paths::ensure_dir(parent)?;
            }
            let (kind, written) = load_entry(key, profile_aad, &relative, &path, &destination)?;
            debug_assert!(kind == KIND_FILE || kind == KIND_SYMLINK);
            stats.entries += 1;
            stats.bytes += written;
        }
    }

    Ok(stats)
}

/// Шифрует один файл с диска в контейнер.
fn store_file(
    key: &[u8; KEY_LEN],
    profile_aad: &[u8],
    relative: &str,
    source: &Path,
    destination: &Path,
) -> Result<u64> {
    let length = fs::metadata(source)?.len();
    let mut reader = BufReader::new(File::open(source)?);
    let mut writer = BufWriter::new(File::create(destination)?);

    write_header(&mut writer, KIND_FILE, length)?;

    let mut remaining = length;
    let mut index = 0u64;
    let mut buffer = Zeroizing::new(vec![0u8; CHUNK_SIZE]);

    while remaining > 0 {
        let take = remaining.min(CHUNK_SIZE as u64) as usize;
        reader.read_exact(&mut buffer[..take])?;

        let chunk = Zeroizing::new(buffer[..take].to_vec());
        let aad = chunk_aad(
            profile_aad,
            relative,
            KIND_FILE,
            index,
            length,
            take as u32,
            false,
        );
        let sealed = crypto::seal(key, &aad, &chunk)?;
        writer.write_all(&sealed)?;

        remaining -= take as u64;
        index += 1;
    }

    write_final_record(&mut writer, key, profile_aad, relative, KIND_FILE, length)?;
    writer.flush()?;
    Ok(length)
}

/// Шифрует содержимое, известное в памяти (цель символической ссылки).
fn store_entry(
    key: &[u8; KEY_LEN],
    profile_aad: &[u8],
    relative: &str,
    kind: u8,
    payload: &[u8],
    destination: &Path,
) -> Result<()> {
    let mut writer = BufWriter::new(File::create(destination)?);
    let length = payload.len() as u64;
    write_header(&mut writer, kind, length)?;

    let mut index = 0u64;
    let mut remaining = payload;
    while !remaining.is_empty() {
        let take = remaining.len().min(CHUNK_SIZE);
        let (part, rest) = remaining.split_at(take);
        let aad = chunk_aad(
            profile_aad,
            relative,
            kind,
            index,
            length,
            take as u32,
            false,
        );
        writer.write_all(&crypto::seal(key, &aad, part)?)?;
        remaining = rest;
        index += 1;
    }

    write_final_record(&mut writer, key, profile_aad, relative, kind, length)?;
    writer.flush()?;
    Ok(())
}

/// Разворачивает один файл контейнера на диск. Возвращает вид и число байт.
fn load_entry(
    key: &[u8; KEY_LEN],
    profile_aad: &[u8],
    relative: &str,
    source: &Path,
    destination: &Path,
) -> Result<(u8, u64)> {
    let file_length = fs::metadata(source)?.len();
    let mut reader = BufReader::new(File::open(source)?);

    let (kind, length) = read_header(&mut reader, relative)?;
    let chunks = chunk_count(length);

    // Каждая запись занимает минимум nonce и тег: если файл короче,
    // нет смысла пытаться что-то читать.
    let minimum =
        HEADER_LEN as u64 + chunks * (NONCE_LEN + TAG_LEN) as u64 + (NONCE_LEN + TAG_LEN) as u64;
    if file_length < minimum {
        return Err(VaultError::Corrupted(format!(
            "файл контейнера обрезан: {relative}"
        )));
    }

    // Ссылка разворачивается в память: цель короткая, а создавать её нужно
    // после проверки подлинности всех записей.
    let is_symlink = kind == KIND_SYMLINK;
    let mut collected: Option<Vec<u8>> = if is_symlink {
        Some(Vec::with_capacity(length as usize))
    } else {
        None
    };

    let mut writer = if is_symlink {
        None
    } else {
        Some(BufWriter::new(File::create(destination)?))
    };

    let mut remaining = length;
    let mut index = 0u64;
    while remaining > 0 {
        let take = remaining.min(CHUNK_SIZE as u64) as usize;
        let sealed = read_exact_vec(&mut reader, NONCE_LEN + take + TAG_LEN, relative)?;
        let aad = chunk_aad(
            profile_aad,
            relative,
            kind,
            index,
            length,
            take as u32,
            false,
        );
        let plain = crypto::open(key, &aad, &sealed).map_err(|_| {
            VaultError::Corrupted(format!(
                "данные профиля не прошли проверку подлинности: {relative}, запись {index}"
            ))
        })?;

        match writer.as_mut() {
            Some(out) => out.write_all(&plain)?,
            None => collected
                .as_mut()
                .expect("ссылка собирается в память")
                .extend_from_slice(&plain),
        }

        remaining -= take as u64;
        index += 1;
    }

    // Финальный маркер подтверждает длину из заголовка и конец файла.
    let sealed_final = read_exact_vec(&mut reader, NONCE_LEN + TAG_LEN, relative)?;
    let aad = chunk_aad(profile_aad, relative, kind, index, length, 0, true);
    crypto::open(key, &aad, &sealed_final).map_err(|_| {
        VaultError::Corrupted(format!(
            "файл контейнера обрезан или заголовок подменён: {relative}"
        ))
    })?;

    let mut extra = [0u8; 1];
    if reader.read(&mut extra)? != 0 {
        return Err(VaultError::Corrupted(format!(
            "в файле контейнера есть лишние данные: {relative}"
        )));
    }

    if let Some(target) = collected {
        let text = String::from_utf8(target).map_err(|_| {
            VaultError::Corrupted(format!("цель ссылки не является текстом: {relative}"))
        })?;
        write_symlink(Path::new(&text), destination)?;
    } else if let Some(mut out) = writer {
        out.flush()?;
    }

    Ok((kind, length))
}

/// Пишет заголовок контейнера.
fn write_header<W: Write>(writer: &mut W, kind: u8, length: u64) -> Result<()> {
    let mut header = [0u8; HEADER_LEN];
    header[..4].copy_from_slice(&MAGIC);
    header[4] = VERSION;
    header[5] = kind;
    header[6..10].copy_from_slice(&(CHUNK_SIZE as u32).to_le_bytes());
    header[10..18].copy_from_slice(&length.to_le_bytes());
    writer.write_all(&header)?;
    Ok(())
}

/// Читает и проверяет заголовок контейнера.
fn read_header<R: Read>(reader: &mut R, relative: &str) -> Result<(u8, u64)> {
    let mut header = [0u8; HEADER_LEN];
    reader.read_exact(&mut header).map_err(|_| {
        VaultError::Corrupted(format!("заголовок контейнера не читается: {relative}"))
    })?;

    if header[..4] != MAGIC {
        return Err(VaultError::Corrupted(format!(
            "не файл контейнера FousBrowser: {relative}"
        )));
    }
    if header[4] != VERSION {
        return Err(VaultError::Corrupted(format!(
            "версия контейнера {} не поддерживается: {relative}",
            header[4]
        )));
    }
    let kind = header[5];
    if kind != KIND_FILE && kind != KIND_SYMLINK {
        return Err(VaultError::Corrupted(format!(
            "неизвестный вид записи {kind}: {relative}"
        )));
    }
    let chunk_size = u32::from_le_bytes([header[6], header[7], header[8], header[9]]) as usize;
    if chunk_size == 0 || chunk_size > MAX_CHUNK_SIZE {
        return Err(VaultError::Corrupted(format!(
            "недопустимый размер записи {chunk_size}: {relative}"
        )));
    }

    let length = u64::from_le_bytes([
        header[10], header[11], header[12], header[13], header[14], header[15], header[16],
        header[17],
    ]);
    Ok((kind, length))
}

/// Записывает финальный маркер.
fn write_final_record<W: Write>(
    writer: &mut W,
    key: &[u8; KEY_LEN],
    profile_aad: &[u8],
    relative: &str,
    kind: u8,
    length: u64,
) -> Result<()> {
    let index = chunk_count(length);
    let aad = chunk_aad(profile_aad, relative, kind, index, length, 0, true);
    let sealed = crypto::seal(key, &aad, &[])?;
    writer.write_all(&sealed)?;
    Ok(())
}

/// Число записей с данными для файла указанной длины.
fn chunk_count(length: u64) -> u64 {
    length.div_ceil(CHUNK_SIZE as u64)
}

/// Собирает AAD одной записи.
fn chunk_aad(
    profile_aad: &[u8],
    relative: &str,
    kind: u8,
    index: u64,
    length: u64,
    chunk_len: u32,
    final_chunk: bool,
) -> Vec<u8> {
    let mut aad = Vec::with_capacity(AAD_PREFIX.len() + profile_aad.len() + relative.len() + 48);
    aad.extend_from_slice(AAD_PREFIX);
    aad.push(0);
    aad.extend_from_slice(profile_aad);
    aad.push(0);
    aad.extend_from_slice(relative.as_bytes());
    aad.push(0);
    aad.push(kind);
    aad.push(if final_chunk { FINAL_FLAG } else { DATA_FLAG });
    aad.extend_from_slice(&index.to_le_bytes());
    aad.extend_from_slice(&length.to_le_bytes());
    aad.extend_from_slice(&chunk_len.to_le_bytes());
    aad
}

/// Читает ровно `len` байт или сообщает о повреждении.
fn read_exact_vec<R: Read>(reader: &mut R, len: usize, relative: &str) -> Result<Vec<u8>> {
    let mut buffer = vec![0u8; len];
    reader
        .read_exact(&mut buffer)
        .map_err(|_| VaultError::Corrupted(format!("файл контейнера обрезан: {relative}")))?;
    Ok(buffer)
}

/// Проверяет, что относительный путь безопасен.
///
/// Имена внутри контейнера не аутентифицированы, поэтому путь вида `../../x`,
/// `/etc/passwd` или `C:\Windows` отвергается: иначе распаковка записала бы
/// файлы за пределами каталога профиля.
pub fn validate_relative(relative: &str) -> Result<()> {
    if relative.is_empty() {
        return Err(VaultError::Corrupted(
            "пустое имя в контейнере профиля".into(),
        ));
    }
    for component in Path::new(relative).components() {
        match component {
            Component::Normal(name) => {
                let text = name.to_string_lossy();
                // Обратный слэш на Unix — обычный символ имени, а на Windows —
                // разделитель. Контейнер, собранный на Unix, на Windows вёл бы
                // себя иначе, поэтому такие имена отвергаются сразу.
                if text.is_empty() || text.contains('\0') || text.contains('\\') {
                    return Err(VaultError::Corrupted(format!(
                        "недопустимое имя в контейнере профиля: {relative}"
                    )));
                }
            }
            _ => {
                return Err(VaultError::Corrupted(format!(
                    "недопустимый путь в контейнере профиля: {relative}"
                )))
            }
        }
    }
    Ok(())
}

/// Создаёт символическую ссылку.
#[cfg(unix)]
fn write_symlink(target: &Path, destination: &Path) -> Result<()> {
    std::os::unix::fs::symlink(target, destination)?;
    Ok(())
}

/// На Windows символические ссылки требуют особых прав, поэтому цель
/// сохраняется как обычный файл: содержимое не теряется, а браузерные
/// профили такими ссылками не пользуются.
#[cfg(not(unix))]
fn write_symlink(target: &Path, destination: &Path) -> Result<()> {
    let mut file = File::create(destination)?;
    file.write_all(target.to_string_lossy().as_bytes())?;
    Ok(())
}

/// Полный путь каталога-сборки (для диагностики и тестов).
pub fn staging_dir(profiles_root: &Path, profile_id: &str) -> PathBuf {
    profiles_root.join(format!("{profile_id}{STAGING_SUFFIX}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vault::kdf::KdfParams;
    use crate::vault::metadata::ProfileKind;
    use crate::vault::session::Vault;

    const PASSWORD: &str = "correct-horse-battery";

    fn vault(dir: &Path) -> UnlockedVault {
        Vault::create_with_params(
            dir,
            PASSWORD,
            KdfParams {
                algorithm: "argon2id".to_string(),
                m_cost_kib: 64,
                t_cost: 1,
                p_cost: 1,
            },
        )
        .unwrap()
    }

    fn make_profile(vault: &mut UnlockedVault) -> String {
        vault
            .create_profile("Профиль", ProfileKind::Normal, None, None)
            .unwrap()
            .id
    }

    /// Детерминированный «шум»: тесты не должны зависеть от генератора ОС.
    fn filler(len: usize) -> Vec<u8> {
        let mut out = Vec::with_capacity(len);
        let mut state = 0x1234_5678u32;
        for _ in 0..len {
            state = state.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
            out.push((state >> 16) as u8);
        }
        out
    }

    fn seal_round_trip(vault: &UnlockedVault, id: &str) -> PathBuf {
        let plain = vault.temp_profile_dir(id);
        vault.seal_profile(id, &plain).unwrap();
        wipe_dir(&plain).unwrap();
        vault.unseal_profile(id, &plain).unwrap();
        plain
    }

    #[test]
    fn seal_and_unseal_restore_the_tree() {
        let tmp = tempfile::tempdir().unwrap();
        let mut vault = vault(tmp.path());
        let id = make_profile(&mut vault);
        let plain = vault.temp_profile_dir(&id);

        fs::create_dir_all(plain.join("Default/Cache")).unwrap();
        fs::create_dir_all(plain.join("Empty")).unwrap();
        fs::write(plain.join("Cookies"), b"cookie-data").unwrap();
        fs::write(plain.join("Default/Preferences"), b"{\"x\":1}").unwrap();

        let stats = vault.seal_profile(&id, &plain).unwrap();
        assert_eq!(stats.entries, 2);
        assert_eq!(stats.bytes, 11 + 7);

        // В контейнере нет открытого текста, но есть сигнатура формата.
        let raw = fs::read(vault.profile_dir(&id).join("Cookies")).unwrap();
        assert_eq!(&raw[..4], &MAGIC);
        assert!(
            !raw.windows(11).any(|window| window == b"cookie-data"),
            "открытый текст не должен попадать в контейнер"
        );
        assert!(container_exists(&vault.profile_dir(&id)));

        wipe_dir(&plain).unwrap();
        let back = vault.unseal_profile(&id, &plain).unwrap();
        assert_eq!(back.entries, 2);
        assert_eq!(fs::read(plain.join("Cookies")).unwrap(), b"cookie-data");
        assert_eq!(
            fs::read(plain.join("Default/Preferences")).unwrap(),
            b"{\"x\":1}"
        );
        assert!(plain.join("Empty").is_dir(), "пустой каталог сохраняется");
    }

    #[test]
    fn files_larger_than_one_chunk_round_trip() {
        let tmp = tempfile::tempdir().unwrap();
        let mut vault = vault(tmp.path());
        let id = make_profile(&mut vault);
        let plain = vault.temp_profile_dir(&id);
        paths::ensure_dir(&plain).unwrap();

        let data = filler(CHUNK_SIZE * 2 + 1234);
        fs::write(plain.join("History"), &data).unwrap();
        vault.seal_profile(&id, &plain).unwrap();

        let container = fs::metadata(vault.profile_dir(&id).join("History"))
            .unwrap()
            .len();
        let expected =
            (HEADER_LEN + data.len() + 3 * (NONCE_LEN + TAG_LEN) + (NONCE_LEN + TAG_LEN)) as u64;
        assert_eq!(container, expected);

        let back = seal_round_trip(&vault, &id);
        assert_eq!(fs::read(back.join("History")).unwrap(), data);
    }

    #[test]
    fn empty_file_round_trips() {
        let tmp = tempfile::tempdir().unwrap();
        let mut vault = vault(tmp.path());
        let id = make_profile(&mut vault);
        let plain = vault.temp_profile_dir(&id);
        paths::ensure_dir(&plain).unwrap();
        fs::write(plain.join("SingletonLock"), b"").unwrap();

        vault.seal_profile(&id, &plain).unwrap();
        let back = seal_round_trip(&vault, &id);
        assert_eq!(
            fs::read(back.join("SingletonLock")).unwrap(),
            Vec::<u8>::new()
        );
    }

    #[test]
    fn reordered_chunks_are_detected() {
        let tmp = tempfile::tempdir().unwrap();
        let mut vault = vault(tmp.path());
        let id = make_profile(&mut vault);
        let plain = vault.temp_profile_dir(&id);
        paths::ensure_dir(&plain).unwrap();
        fs::write(plain.join("History"), filler(CHUNK_SIZE * 3)).unwrap();
        vault.seal_profile(&id, &plain).unwrap();

        let file = vault.profile_dir(&id).join("History");
        let mut raw = fs::read(&file).unwrap();
        let record = NONCE_LEN + CHUNK_SIZE + TAG_LEN;
        let first = raw[HEADER_LEN..HEADER_LEN + record].to_vec();
        let second = raw[HEADER_LEN + record..HEADER_LEN + 2 * record].to_vec();
        raw[HEADER_LEN..HEADER_LEN + record].copy_from_slice(&second);
        raw[HEADER_LEN + record..HEADER_LEN + 2 * record].copy_from_slice(&first);
        fs::write(&file, &raw).unwrap();

        assert!(matches!(
            vault.unseal_profile(&id, &plain),
            Err(VaultError::Corrupted(_))
        ));
    }

    #[test]
    fn header_tampering_is_detected() {
        let tmp = tempfile::tempdir().unwrap();
        let mut vault = vault(tmp.path());
        let id = make_profile(&mut vault);
        let plain = vault.temp_profile_dir(&id);
        paths::ensure_dir(&plain).unwrap();
        fs::write(plain.join("Cookies"), b"short").unwrap();
        vault.seal_profile(&id, &plain).unwrap();

        let file = vault.profile_dir(&id).join("Cookies");
        let mut raw = fs::read(&file).unwrap();
        // Уменьшаем заявленную длину файла: финальный маркер перестанет сходиться.
        raw[10..18].copy_from_slice(&3u64.to_le_bytes());
        fs::write(&file, &raw).unwrap();

        assert!(matches!(
            vault.unseal_profile(&id, &plain),
            Err(VaultError::Corrupted(_))
        ));
    }

    #[test]
    fn truncation_is_detected() {
        let tmp = tempfile::tempdir().unwrap();
        let mut vault = vault(tmp.path());
        let id = make_profile(&mut vault);
        let plain = vault.temp_profile_dir(&id);
        paths::ensure_dir(&plain).unwrap();
        fs::write(plain.join("Cookies"), b"cookie-data").unwrap();
        vault.seal_profile(&id, &plain).unwrap();

        let file = vault.profile_dir(&id).join("Cookies");
        let raw = fs::read(&file).unwrap();
        fs::write(&file, &raw[..raw.len() - (NONCE_LEN + TAG_LEN)]).unwrap();

        assert!(matches!(
            vault.unseal_profile(&id, &plain),
            Err(VaultError::Corrupted(_))
        ));
    }

    #[test]
    fn truncated_to_header_only_is_detected() {
        let tmp = tempfile::tempdir().unwrap();
        let mut vault = vault(tmp.path());
        let id = make_profile(&mut vault);
        let plain = vault.temp_profile_dir(&id);
        paths::ensure_dir(&plain).unwrap();
        fs::write(plain.join("Cookies"), b"cookie-data").unwrap();
        vault.seal_profile(&id, &plain).unwrap();

        let file = vault.profile_dir(&id).join("Cookies");
        let raw = fs::read(&file).unwrap();
        fs::write(&file, &raw[..HEADER_LEN]).unwrap();

        assert!(matches!(
            vault.unseal_profile(&id, &plain),
            Err(VaultError::Corrupted(_))
        ));
    }

    #[test]
    fn container_from_another_profile_is_rejected() {
        let tmp = tempfile::tempdir().unwrap();
        let mut vault = vault(tmp.path());
        let first = make_profile(&mut vault);
        let second = make_profile(&mut vault);

        let plain = vault.temp_profile_dir(&first);
        paths::ensure_dir(&plain).unwrap();
        fs::write(plain.join("Login Data"), b"credentials").unwrap();
        vault.seal_profile(&first, &plain).unwrap();

        // Подкладываем контейнер первого профиля второму под тем же именем.
        let stolen = vault.profile_dir(&first).join("Login Data");
        let target = vault.profile_dir(&second).join("Login Data");
        fs::copy(&stolen, &target).unwrap();

        let destination = vault.temp_profile_dir(&second);
        assert!(matches!(
            vault.unseal_profile(&second, &destination),
            Err(VaultError::Corrupted(_))
        ));
    }

    #[test]
    fn renamed_file_is_rejected() {
        let tmp = tempfile::tempdir().unwrap();
        let mut vault = vault(tmp.path());
        let id = make_profile(&mut vault);
        let plain = vault.temp_profile_dir(&id);
        paths::ensure_dir(&plain).unwrap();
        fs::write(plain.join("Cookies"), b"cookie-data").unwrap();
        vault.seal_profile(&id, &plain).unwrap();

        // Путь входит в AAD: другое имя делает контейнер недействительным.
        let dir = vault.profile_dir(&id);
        fs::rename(dir.join("Cookies"), dir.join("Bookmarks")).unwrap();

        assert!(matches!(
            vault.unseal_profile(&id, &plain),
            Err(VaultError::Corrupted(_))
        ));
    }

    #[test]
    fn resealing_replaces_the_container_without_leftovers() {
        let tmp = tempfile::tempdir().unwrap();
        let mut vault = vault(tmp.path());
        let id = make_profile(&mut vault);
        let plain = vault.temp_profile_dir(&id);
        paths::ensure_dir(&plain).unwrap();

        fs::write(plain.join("Cookies"), b"first").unwrap();
        vault.seal_profile(&id, &plain).unwrap();
        fs::write(plain.join("Cookies"), b"second").unwrap();
        vault.seal_profile(&id, &plain).unwrap();

        wipe_dir(&plain).unwrap();
        vault.unseal_profile(&id, &plain).unwrap();
        assert_eq!(fs::read(plain.join("Cookies")).unwrap(), b"second");

        // Никаких следов сборки рядом с профилем.
        let profiles_root = vault.profile_dir(&id).parent().unwrap().to_path_buf();
        let leftovers: Vec<String> = fs::read_dir(&profiles_root)
            .unwrap()
            .map(|entry| entry.unwrap().file_name().to_string_lossy().to_string())
            .filter(|name| name.ends_with(STAGING_SUFFIX) || name.ends_with(PREVIOUS_SUFFIX))
            .collect();
        assert!(
            leftovers.is_empty(),
            "остались служебные каталоги: {leftovers:?}"
        );
    }

    #[test]
    fn unsealing_a_profile_without_container_gives_empty_directory() {
        let tmp = tempfile::tempdir().unwrap();
        let mut vault = vault(tmp.path());
        let id = make_profile(&mut vault);
        wipe_dir(&vault.profile_dir(&id)).unwrap();

        let plain = vault.temp_profile_dir(&id);
        let stats = vault.unseal_profile(&id, &plain).unwrap();
        assert_eq!(stats, ContainerStats::default());
        assert!(plain.is_dir());
    }

    #[test]
    fn plaintext_state_reports_presence_and_discard_removes_it() {
        let tmp = tempfile::tempdir().unwrap();
        let mut vault = vault(tmp.path());
        let id = make_profile(&mut vault);

        assert_eq!(vault.plaintext_state(&id).unwrap(), PlaintextState::Absent);

        let plain = vault.temp_profile_dir(&id);
        paths::ensure_dir(&plain).unwrap();
        fs::write(plain.join("Cookies"), b"12345").unwrap();
        assert_eq!(
            vault.plaintext_state(&id).unwrap(),
            PlaintextState::Present {
                entries: 1,
                bytes: 5
            }
        );

        vault.discard_plaintext(&id).unwrap();
        assert_eq!(vault.plaintext_state(&id).unwrap(), PlaintextState::Absent);
        assert!(!plain.exists());
    }

    #[test]
    fn sealing_an_unknown_profile_fails_before_touching_the_disk() {
        let tmp = tempfile::tempdir().unwrap();
        let vault = vault(tmp.path());
        let unknown = "11111111-2222-3333-4444-555555555555";
        assert!(matches!(
            vault.seal_profile(unknown, tmp.path()),
            Err(VaultError::NotFound(_))
        ));
    }

    #[test]
    fn vanished_files_are_distinguished_from_locked_ones() {
        // Исчезнувший файл можно пропустить, заблокированный — нельзя:
        // во втором случае данные ещё существуют и должны попасть в контейнер.
        let missing = std::io::Error::new(std::io::ErrorKind::NotFound, "нет файла");
        assert!(vanished(&missing));
        assert!(is_vanished(&VaultError::Io(missing)));

        let locked = std::io::Error::new(std::io::ErrorKind::PermissionDenied, "занят");
        assert!(!vanished(&locked));
        assert!(!is_vanished(&VaultError::Io(locked)));
        assert!(!is_vanished(&VaultError::Invalid("иное".into())));
    }

    #[test]
    fn sealing_a_missing_directory_is_refused() {
        let tmp = tempfile::tempdir().unwrap();
        let mut vault = vault(tmp.path());
        let id = make_profile(&mut vault);
        assert!(matches!(
            vault.seal_profile(&id, &tmp.path().join("нет-такого")),
            Err(VaultError::Invalid(_))
        ));
    }

    #[test]
    fn relative_paths_are_validated() {
        assert!(validate_relative("Cookies").is_ok());
        assert!(validate_relative("Default/Preferences").is_ok());
        assert!(validate_relative("Default/Cache/data_1").is_ok());

        assert!(validate_relative("").is_err());
        assert!(validate_relative("../escape").is_err());
        assert!(validate_relative("a/../../b").is_err());
        // Ведущая точка — это компонент CurDir, а не обычное имя: в контейнере
        // такие имена не появляются, поэтому путь отвергается.
        assert!(validate_relative("./a").is_err());

        #[cfg(unix)]
        assert!(validate_relative("/etc/passwd").is_err());
        #[cfg(windows)]
        {
            assert!(validate_relative("C:/Windows/system32").is_err());
            assert!(validate_relative("..\\escape").is_err());
        }
    }

    #[cfg(unix)]
    #[test]
    fn symlinks_are_preserved() {
        let tmp = tempfile::tempdir().unwrap();
        let mut vault = vault(tmp.path());
        let id = make_profile(&mut vault);
        let plain = vault.temp_profile_dir(&id);
        paths::ensure_dir(&plain).unwrap();
        std::os::unix::fs::symlink("target-file", plain.join("link")).unwrap();

        vault.seal_profile(&id, &plain).unwrap();
        let back = seal_round_trip(&vault, &id);

        let meta = fs::symlink_metadata(back.join("link")).unwrap();
        assert!(meta.file_type().is_symlink());
        assert_eq!(
            fs::read_link(back.join("link")).unwrap(),
            Path::new("target-file")
        );
    }
}
