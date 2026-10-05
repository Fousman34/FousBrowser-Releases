//! Rewrap only the browser's legacy per-user DPAPI key during an authorized transfer.
use super::{Result, VaultError};
use windows_sys::Win32::{
    Foundation::LocalFree,
    Security::Cryptography::{CryptProtectData, CryptUnprotectData, CRYPT_INTEGER_BLOB},
};
use zeroize::{Zeroize, Zeroizing};

pub fn transform(bytes: &[u8], protect: bool) -> Result<Zeroizing<Vec<u8>>> {
    if bytes.is_empty() || bytes.len() > 65536 {
        return Err(VaultError::Invalid("Неверная длина ключа Windows".into()));
    }
    let input = CRYPT_INTEGER_BLOB {
        cbData: bytes.len() as u32,
        pbData: bytes.as_ptr() as *mut u8,
    };
    let mut output = CRYPT_INTEGER_BLOB {
        cbData: 0,
        pbData: std::ptr::null_mut(),
    };
    // Both APIs allocate output with LocalAlloc; UI is forbidden (flag 1).
    let ok = unsafe {
        if protect {
            CryptProtectData(
                &input,
                std::ptr::null(),
                std::ptr::null(),
                std::ptr::null(),
                std::ptr::null(),
                1,
                &mut output,
            )
        } else {
            CryptUnprotectData(
                &input,
                std::ptr::null_mut(),
                std::ptr::null(),
                std::ptr::null(),
                std::ptr::null(),
                1,
                &mut output,
            )
        }
    };
    if ok == 0 {
        return Err(VaultError::Invalid("Windows не разрешила перенос ключа браузера: экспортируйте профиль под исходной учётной записью Windows".into()));
    }
    let result = unsafe {
        let buffer = std::slice::from_raw_parts_mut(output.pbData, output.cbData as usize);
        let copy = Zeroizing::new(buffer.to_vec());
        buffer.zeroize();
        LocalFree(output.pbData.cast());
        copy
    };
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn key_can_be_rewrapped_for_the_current_windows_account() {
        let key = [37u8; 32];
        let protected = transform(&key, true).unwrap();
        let plain = transform(&protected, false).unwrap();
        assert_eq!(&plain[..], &key);
        let imported = transform(&plain, true).unwrap();
        assert_eq!(&transform(&imported, false).unwrap()[..], &key);
    }
}
