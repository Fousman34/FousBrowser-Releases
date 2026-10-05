//! Live installer check. Uses only the explicit, isolated destination argument.
use fousbrowser_launcher_lib::updater::{self, channel, download, install, Platform};
use std::path::PathBuf;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let root = PathBuf::from(
        std::env::args()
            .nth(1)
            .ok_or("provide a test destination")?,
    );
    let releases = download::fetch_text(&updater::releases_url())?;
    let mut release = channel::antidetect_release(&releases, Platform::WindowsX64, None)?
        .ok_or("no Antidetect release")?;
    if std::env::args().nth(2).as_deref() == Some("mirror") {
        release.asset_url.push_str(".missing");
        release.sums_url.as_mut().unwrap().push_str(".missing");
        release.signature_url.as_mut().unwrap().push_str(".missing");
    }
    println!("Selected {}: {}", release.version, release.asset_name);
    let mut percent = 0;
    let prepared = install::prepare(
        &release,
        &root,
        Platform::WindowsX64,
        |p| {
            let next = p.percent().unwrap_or(0.0) as u32 / 10;
            if next != percent {
                println!("{}%", next * 10);
                percent = next;
            }
        },
        |line| println!("{line}"),
    )?;
    println!(
        "{}",
        install::install(&prepared, &root, Platform::WindowsX64, |line| println!(
            "{line}"
        ))?
        .display()
    );
    Ok(())
}
