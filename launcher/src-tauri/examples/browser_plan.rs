//! Emits the actual launch plan for isolated browser integration checks.
use fousbrowser_launcher_lib::{
    engine::{flags, startpage},
    vault::{ProfileKind, Vault},
};
use std::path::PathBuf;
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let root = PathBuf::from(std::env::args().nth(1).ok_or("provide isolated root")?);
    let kind = if std::env::args().nth(2).as_deref() == Some("antidetect") {
        ProfileKind::Antidetect
    } else {
        ProfileKind::Normal
    };
    let restore = std::env::args().nth(3).as_deref() != Some("fresh");
    let vault_dir = root.join("vault");
    let password = "Integration-test-only-42!";
    let mut vault = if vault_dir.join("header.json").exists() {
        Vault::open(&vault_dir)?.unlock(password)?
    } else {
        Vault::create(&vault_dir, password)?
    };
    let profile = if let Some(p) = vault.profiles().first() {
        p.clone()
    } else {
        vault.create_profile("Integration", kind, None, None)?
    };
    let plain = vault.temp_profile_dir(&profile.id);
    if std::env::args().nth(3).as_deref() == Some("seal") {
        vault.seal_profile(&profile.id, &plain)?;
        vault.discard_plaintext(&profile.id)?;
        println!("[]");
        return Ok(());
    }
    let profile =
        vault.update_profile_with_tabs(&profile.id, "Integration", kind, None, restore)?;
    if !plain.exists() {
        vault.unseal_profile(&profile.id, &plain)?;
    }
    let page = startpage::ensure(&root)?;
    let plan = flags::build(&profile, &plain, None, page.parent());
    println!("{}", serde_json::to_string(&plan.args)?);
    Ok(())
}
