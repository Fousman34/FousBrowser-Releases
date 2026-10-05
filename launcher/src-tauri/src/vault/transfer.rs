//! Portable profiles: opaque ZIP entries contain existing authenticated ciphertext.
//! A password-encrypted manifest binds every entry, path, hash, profile key and AAD.
//! Import verifies the destination password first and rekeys into a new profile UUID.
use std::fs::{self, File};
use std::io::{Read, Write};
use std::path::Path;

use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;
use zip::{write::SimpleFileOptions, ZipArchive, ZipWriter};

use super::{crypto, cryptofs, kdf, ProfileMeta, Result, UnlockedVault, VaultError};

const AAD: &[u8] = b"fousbrowser/profile-transfer/v1";
const MAX_BYTES: u64 = 20 * 1024 * 1024 * 1024;
const MAX_ENTRIES: usize = 100_000;
const MAX_MANIFEST: u64 = 32 * 1024 * 1024;

#[derive(Serialize, Deserialize)]
struct Entry {
    path: String,
    size: u64,
    hash: String,
}

#[derive(Serialize, Deserialize)]
struct Manifest {
    version: u32,
    profile: ProfileMeta,
    key: [u8; 32],
    aad: Vec<u8>,
    entries: Vec<Entry>,
    #[serde(default)]
    browser_key: Option<Vec<u8>>,
}

impl Drop for Manifest {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.key.zeroize();
        if let Some(key) = self.browser_key.as_mut() {
            key.zeroize();
        }
        if let Some(proxy) = self.profile.proxy.as_mut() {
            if let Some(password) = proxy.password.as_mut() {
                password.zeroize();
            }
        }
    }
}

fn archive_error(error: impl std::fmt::Display) -> VaultError {
    VaultError::Invalid(format!("Архив профиля: {error}"))
}

fn verify_password(vault: &UnlockedVault, password: &str) -> Result<()> {
    let header = vault.header();
    let key = kdf::derive_master_key(password, &header.salt()?, &header.kdf)?;
    let plain = crypto::open(&key, &header.verifier_aad(), &header.verifier()?)
        .map_err(|_| VaultError::WrongPassword)?;
    if plain != super::header::VERIFIER_PLAINTEXT {
        return Err(VaultError::WrongPassword);
    }
    Ok(())
}

fn hash_file(path: &Path) -> Result<(u64, String)> {
    let mut file = File::open(path)?;
    let mut hasher = Sha256::new();
    let mut buffer = [0u8; 65536];
    let mut size = 0;
    loop {
        let count = file.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        size += count as u64;
        if size > MAX_BYTES {
            return Err(archive_error("файл больше 20 ГиБ"));
        }
        hasher.update(&buffer[..count]);
    }
    Ok((size, hex::encode(hasher.finalize())))
}

impl UnlockedVault {
    pub fn export_profile(&self, id: &str, password: &str, destination: &Path) -> Result<()> {
        verify_password(self, password)?;
        if self.temp_profile_dir(id).exists() {
            return Err(archive_error(
                "сначала остановите профиль и зашифруйте данные",
            ));
        }
        let profile = self
            .metadata()
            .find(id)
            .cloned()
            .ok_or_else(|| VaultError::NotFound("профиль".into()))?;
        let parent = destination
            .parent()
            .ok_or_else(|| archive_error("неверный путь"))?;
        let mut output = tempfile::NamedTempFile::new_in(parent)?;
        let mut zip = ZipWriter::new(output.as_file_mut());
        let options =
            SimpleFileOptions::default().compression_method(zip::CompressionMethod::Stored);
        let salt = crypto::random_bytes::<16>()?;
        let key = kdf::derive_master_key(password, &salt, &kdf::KdfParams::default())?;
        zip.start_file("FBP1", options).map_err(archive_error)?;
        zip.write_all(&salt)?;
        let mut manifest = Manifest {
            version: 1,
            profile,
            key: *self.profile_key(id)?,
            aad: self.profile_aad(id),
            entries: Vec::new(),
            browser_key: None,
        };
        let root = self.profile_dir(id);
        // Local State is a small encrypted entry. Its temporary plaintext is wiped.
        if root.join("Local State").is_file() {
            let scratch = tempfile::tempdir_in(self.dir())?;
            let local = scratch.path().join("Local State");
            let result = (|| -> Result<Option<Vec<u8>>> {
                cryptofs::load_entry(
                    &manifest.key,
                    &manifest.aad,
                    "Local State",
                    &root.join("Local State"),
                    &local,
                )?;
                let bytes = Zeroizing::new(fs::read(&local)?);
                let state: serde_json::Value = serde_json::from_slice(&bytes)?;
                let Some(encoded) = state
                    .pointer("/os_crypt/encrypted_key")
                    .and_then(|v| v.as_str())
                else {
                    return Ok(None);
                };
                let wrapped = B64.decode(encoded).map_err(archive_error)?;
                let Some(dpapi) = wrapped.strip_prefix(b"DPAPI") else {
                    return Ok(None);
                };
                Ok(Some(super::windows_key::transform(dpapi, false)?.to_vec()))
            })();
            super::wipe_dir(scratch.path())?;
            manifest.browser_key = result?;
        }
        let mut stack = vec![root.clone()];
        let mut total = 0u64;
        while let Some(dir) = stack.pop() {
            for entry in fs::read_dir(dir)? {
                let entry = entry?;
                let kind = entry.file_type()?;
                if kind.is_dir() {
                    stack.push(entry.path());
                    continue;
                }
                if !kind.is_file() {
                    return Err(archive_error("ссылка в зашифрованном контейнере"));
                }
                let path = entry.path();
                let relative = path
                    .strip_prefix(&root)
                    .map_err(archive_error)?
                    .to_str()
                    .ok_or_else(|| archive_error("неверное имя файла"))?
                    .replace('\\', "/");
                cryptofs::validate_relative(&relative)?;
                let (size, hash) = hash_file(&path)?;
                total += size;
                if total > MAX_BYTES || manifest.entries.len() >= MAX_ENTRIES {
                    return Err(archive_error("предел экспорта: 20 ГиБ / 100000 файлов"));
                }
                zip.start_file(format!("data/{}", manifest.entries.len()), options)
                    .map_err(archive_error)?;
                std::io::copy(&mut File::open(path)?, &mut zip)?;
                manifest.entries.push(Entry {
                    path: relative,
                    size,
                    hash,
                });
            }
        }
        let plain = Zeroizing::new(serde_json::to_vec(&manifest)?);
        if plain.len() as u64 > MAX_MANIFEST - 40 {
            return Err(archive_error("слишком большой манифест"));
        }
        let sealed = crypto::seal(&key, AAD, &plain)?;
        zip.start_file("manifest.enc", options)
            .map_err(archive_error)?;
        zip.write_all(&sealed)?;
        zip.finish().map_err(archive_error)?;
        output.as_file().sync_all()?;
        output
            .persist_noclobber(destination)
            .map_err(archive_error)?;
        Ok(())
    }

    pub fn import_profile(&mut self, password: &str, source: &Path) -> Result<ProfileMeta> {
        verify_password(self, password)?;
        if fs::metadata(source)?.len() > MAX_BYTES + MAX_MANIFEST + 32 * 1024 * 1024 {
            return Err(archive_error("архив слишком большой"));
        }
        let mut zip = ZipArchive::new(File::open(source)?).map_err(archive_error)?;
        if zip.len() > MAX_ENTRIES + 2 {
            return Err(archive_error("слишком много файлов"));
        }
        let mut salt = [0u8; 16];
        {
            let mut entry = zip.by_name("FBP1").map_err(archive_error)?;
            if entry.size() != 16 {
                return Err(archive_error("неизвестный формат"));
            }
            entry.read_exact(&mut salt)?;
        }
        let key = kdf::derive_master_key(password, &salt, &kdf::KdfParams::default())?;
        let mut sealed = Vec::new();
        {
            let entry = zip.by_name("manifest.enc").map_err(archive_error)?;
            if entry.size() > MAX_MANIFEST {
                return Err(archive_error("манифест слишком большой"));
            }
            entry.take(MAX_MANIFEST + 1).read_to_end(&mut sealed)?;
        }
        let plain = Zeroizing::new(crypto::open(&key, AAD, &sealed).map_err(|_| {
            archive_error("пароли исходного и текущего хранилища не совпадают либо архив повреждён. Текущее хранилище не изменено")
        })?);
        let manifest: Manifest = serde_json::from_slice(&plain)?;
        if manifest.version != 1 || zip.len() != manifest.entries.len() + 2 {
            return Err(archive_error("неверная версия или неполный архив"));
        }
        manifest.profile.validate().map_err(archive_error)?;
        let staging = tempfile::tempdir_in(self.dir())?;
        let encrypted = staging.path().join("encrypted");
        fs::create_dir(&encrypted)?;
        let mut total = 0u64;
        let mut names = std::collections::HashSet::new();
        for (index, item) in manifest.entries.iter().enumerate() {
            cryptofs::validate_relative(&item.path)?;
            if !names.insert(item.path.to_lowercase()) {
                return Err(archive_error("повторяющийся путь"));
            }
            total = total
                .checked_add(item.size)
                .ok_or_else(|| archive_error("переполнение размера"))?;
            if total > MAX_BYTES {
                return Err(archive_error("архив больше 20 ГиБ"));
            }
            let entry = zip
                .by_name(&format!("data/{index}"))
                .map_err(archive_error)?;
            if entry.size() != item.size {
                return Err(archive_error("изменён размер файла"));
            }
            let path = encrypted.join(&item.path);
            fs::create_dir_all(
                path.parent()
                    .ok_or_else(|| archive_error("неверный путь"))?,
            )?;
            let copied = std::io::copy(&mut entry.take(item.size + 1), &mut File::create(&path)?)?;
            let (size, hash) = hash_file(&path)?;
            if copied != item.size || size != item.size || hash != item.hash {
                return Err(archive_error("файл повреждён или изменён"));
            }
        }
        let mut profile = manifest.profile.clone();
        profile.id = uuid::Uuid::new_v4().to_string();
        // Keep fingerprint identity on transfer; cloning is a separate operation.
        let temp = self.temp_profile_dir(&profile.id);
        fs::create_dir_all(&temp)?;
        let result = (|| {
            cryptofs::read_container(&manifest.key, &manifest.aad, &encrypted, &temp)?;
            if let Some(key) = &manifest.browser_key {
                if key.len() != 32 {
                    return Err(archive_error("неверный ключ браузера"));
                }
                let path = temp.join("Local State");
                let bytes = Zeroizing::new(fs::read(&path)?);
                let mut state: serde_json::Value = serde_json::from_slice(&bytes)?;
                let mut wrapped = b"DPAPI".to_vec();
                wrapped.extend_from_slice(&super::windows_key::transform(key, true)?);
                state["os_crypt"]["encrypted_key"] =
                    serde_json::Value::String(B64.encode(&wrapped));
                crate::paths::write_atomic(&path, &serde_json::to_vec(&state)?)?;
            }
            self.metadata_mut().profiles.push(profile.clone());
            self.seal_profile(&profile.id, &temp)?;
            super::wipe_dir(&temp)?;
            self.save_metadata()?;
            Ok(profile.clone())
        })();
        if result.is_err() {
            self.metadata_mut()
                .profiles
                .retain(|item| item.id != profile.id);
            let _ = super::wipe_dir(&self.profile_dir(&profile.id));
            let _ = super::wipe_dir(&temp);
        }
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vault::{ProfileKind, Vault};
    const PASSWORD: &str = "Transfer-test-password-42!";

    #[test]
    fn transfer_preserves_data_and_rejects_other_password() {
        let tmp = tempfile::tempdir().unwrap();
        let mut first = Vault::create(&tmp.path().join("a"), PASSWORD).unwrap();
        let profile = first
            .create_profile("Portable", ProfileKind::Antidetect, None, None)
            .unwrap();
        let data = tmp.path().join("data");
        fs::create_dir(&data).unwrap();
        fs::write(data.join("Cookies"), b"secret browser contents").unwrap();
        first.seal_profile(&profile.id, &data).unwrap();
        let archive = tmp.path().join("profile.fousprofile");
        first
            .export_profile(&profile.id, PASSWORD, &archive)
            .unwrap();
        let bytes = fs::read(&archive).unwrap();
        assert!(!bytes.windows(7).any(|part| part == b"Cookies"));
        assert!(!bytes.windows(8).any(|part| part == b"Portable"));
        let mut other = Vault::create(&tmp.path().join("b"), "Different-password-42!").unwrap();
        assert!(other
            .import_profile("Different-password-42!", &archive)
            .is_err());
        assert!(other.profiles().is_empty());
        let mut second = Vault::create(&tmp.path().join("c"), PASSWORD).unwrap();
        assert!(second.import_profile("wrong-password", &archive).is_err());
        let imported = second.import_profile(PASSWORD, &archive).unwrap();
        assert_ne!(imported.id, profile.id);
        assert_eq!(imported.seed, profile.seed);
        let restored = tmp.path().join("restored");
        second.unseal_profile(&imported.id, &restored).unwrap();
        assert_eq!(
            fs::read(restored.join("Cookies")).unwrap(),
            b"secret browser contents"
        );
        assert!(!second.temp_profile_dir(&imported.id).exists());
        // Missing or modified ciphertext must not produce a partial imported profile.
        for remove in [true, false] {
            let mut input = ZipArchive::new(std::io::Cursor::new(&bytes)).unwrap();
            let damaged = tmp.path().join("damaged.fousprofile");
            let mut output = ZipWriter::new(File::create(&damaged).unwrap());
            for index in 0..input.len() {
                let mut entry = input.by_index(index).unwrap();
                let name = entry.name().to_string();
                if remove && name == "data/0" {
                    continue;
                }
                let mut content = Vec::new();
                entry.read_to_end(&mut content).unwrap();
                if !remove && name == "data/0" {
                    content[20] ^= 1;
                }
                output
                    .start_file(name, SimpleFileOptions::default())
                    .unwrap();
                output.write_all(&content).unwrap();
            }
            output.finish().unwrap();
            assert!(second.import_profile(PASSWORD, &damaged).is_err());
            assert_eq!(second.profiles().len(), 1);
        }
        // Existing archives are never silently replaced.
        assert!(first
            .export_profile(&profile.id, PASSWORD, &archive)
            .is_err());
        assert_eq!(fs::read(&archive).unwrap(), bytes);
        // Truncation must never add a partial profile.
        fs::write(&archive, &bytes[..bytes.len() / 2]).unwrap();
        assert!(second.import_profile(PASSWORD, &archive).is_err());
        assert_eq!(second.profiles().len(), 1);
    }
}
