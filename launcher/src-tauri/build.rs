use std::path::Path;

fn main() {
    // tauri-build отслеживает только tauri.conf.json и capabilities, но НЕ
    // каталог собранного фронтенда. Без явных указаний ниже изменение
    // интерфейса не приводило бы к пересборке, и в бинарник попадал бы
    // старый UI. Cargo сканирует указанные каталоги рекурсивно.
    println!(
        "cargo:rerun-if-changed={}",
        Path::new("../build").display()
    );

    for path in ["../src", "../static"] {
        if Path::new(path).exists() {
            println!("cargo:rerun-if-changed={path}");
        }
    }

    for file in [
        "../package.json",
        "../svelte.config.js",
        "../vite.config.js",
        "../tsconfig.json",
    ] {
        if Path::new(file).exists() {
            println!("cargo:rerun-if-changed={file}");
        }
    }

    tauri_build::build()
}
