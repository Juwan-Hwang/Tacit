//! Tacit UniFFI 绑定代码生成器。
//!
//! 从编译后的 cdylib 库提取 UniFFI metadata，生成 Kotlin/Swift/Python 绑定代码。
//!
//! # 用法
//!
//! ```sh
//! # 先编译 tacit-ffi cdylib
//! cargo build -p tacit-ffi
//!
//! # 生成 Kotlin 绑定
//! cargo run -p tacit-bindgen -- generate --library target/debug/tacit_ffi.dll --language kotlin --out-dir bindings/kotlin
//!
//! # 生成 Swift 绑定
//! cargo run -p tacit-bindgen -- generate --library target/debug/tacit_ffi.dll --language swift --out-dir bindings/swift
//! ```
//!
//! # 构建流程
//!
//! 1. `cargo build -p tacit-ffi` 生成动态库（`.dylib` / `.so` / `.dll`）。
//! 2. `cargo run -p tacit-bindgen -- generate ...` 从动态库提取 metadata 生成绑定。
//! 3. 将生成的 `.kt` / `.swift` 文件复制到 Android / iOS 项目中。

use std::path::PathBuf;

use camino::Utf8PathBuf;
use clap::{Parser, Subcommand};
use uniffi_bindgen::{
    bindings::{KotlinBindingGenerator, PythonBindingGenerator, SwiftBindingGenerator},
    library_mode, BindgenCrateConfigSupplier, BindingGenerator, EmptyCrateConfigSupplier,
};

#[derive(Parser)]
#[command(name = "tacit-bindgen")]
#[command(about = "Tacit UniFFI 绑定代码生成器")]
#[command(version)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// 从编译后的库文件生成绑定代码（library mode，推荐）。
    Generate {
        /// 编译后的 tacit-ffi cdylib 库文件路径（.dylib / .so / .dll）。
        #[arg(long)]
        library: String,

        /// 目标语言：kotlin / swift / python。
        #[arg(long)]
        language: String,

        /// 输出目录。
        #[arg(long)]
        out_dir: String,

        /// 可选：uniffi.toml 配置文件路径覆盖。
        #[arg(long)]
        config: Option<String>,

        /// 是否格式化生成的代码（默认 true）。
        #[arg(long, default_value_t = true)]
        format: bool,
    },
    /// 从 UDL 源文件生成绑定代码（传统模式，需要 .udl 文件）。
    GenerateFromUdl {
        /// tacit-ffi 的 UDL 文件路径。
        #[arg(long)]
        udl: String,

        /// 目标语言：kotlin / swift / python。
        #[arg(long)]
        language: String,

        /// 输出目录。
        #[arg(long)]
        out_dir: String,

        /// 可选：编译后的 cdylib 库文件路径（用于补充 metadata）。
        #[arg(long)]
        library: Option<String>,

        /// 可选：uniffi.toml 配置文件路径。
        #[arg(long)]
        config: Option<String>,

        /// 可选：crate 名称覆盖。
        #[arg(long)]
        crate_name: Option<String>,

        /// 是否格式化生成的代码（默认 true）。
        #[arg(long, default_value_t = true)]
        format: bool,
    },
}

/// 支持的目标语言。
#[derive(Clone, Copy, PartialEq, Eq)]
enum TargetLanguage {
    Kotlin,
    Swift,
    Python,
}

impl std::str::FromStr for TargetLanguage {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "kotlin" | "kt" => Ok(Self::Kotlin),
            "swift" => Ok(Self::Swift),
            "python" | "py" => Ok(Self::Python),
            other => Err(anyhow::anyhow!(
                "不支持的语言: {other}（可选: kotlin, swift, python）"
            )),
        }
    }
}

/// 根据 target language 创建对应的 BindingGenerator 并生成绑定。
fn generate_with_generator<G: BindingGenerator>(
    library_path: &camino::Utf8Path,
    crate_name: Option<String>,
    generator: &G,
    config_supplier: &dyn BindgenCrateConfigSupplier,
    config_file: Option<&camino::Utf8Path>,
    out_dir: &camino::Utf8Path,
    try_format: bool,
) -> anyhow::Result<()> {
    library_mode::generate_bindings(
        library_path,
        crate_name,
        generator,
        config_supplier,
        config_file,
        out_dir,
        try_format,
    )?;
    Ok(())
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Generate {
            library,
            language,
            out_dir,
            config,
            format,
        } => {
            let lang: TargetLanguage = language.parse()?;
            let library_path = Utf8PathBuf::from(library);
            let out_dir = Utf8PathBuf::from(out_dir);
            let config_path = config.map(Utf8PathBuf::from);
            let config_supplier = EmptyCrateConfigSupplier;

            match lang {
                TargetLanguage::Kotlin => {
                    let generator = KotlinBindingGenerator;
                    generate_with_generator(
                        &library_path,
                        None,
                        &generator,
                        &config_supplier,
                        config_path.as_deref(),
                        &out_dir,
                        format,
                    )?;
                }
                TargetLanguage::Swift => {
                    let generator = SwiftBindingGenerator;
                    generate_with_generator(
                        &library_path,
                        None,
                        &generator,
                        &config_supplier,
                        config_path.as_deref(),
                        &out_dir,
                        format,
                    )?;
                }
                TargetLanguage::Python => {
                    let generator = PythonBindingGenerator;
                    generate_with_generator(
                        &library_path,
                        None,
                        &generator,
                        &config_supplier,
                        config_path.as_deref(),
                        &out_dir,
                        format,
                    )?;
                }
            }

            println!("✓ {lang} 绑定代码已生成到 {out_dir}");
        }
        Commands::GenerateFromUdl {
            udl,
            language,
            out_dir,
            library,
            config,
            crate_name,
            format,
        } => {
            let lang: TargetLanguage = language.parse()?;
            let udl_path = Utf8PathBuf::from(udl);
            let out_dir_override = Some(Utf8PathBuf::from(out_dir));
            let library_file = library.map(Utf8PathBuf::from);
            let config_file = config.map(Utf8PathBuf::from);

            match lang {
                TargetLanguage::Kotlin => {
                    let generator = KotlinBindingGenerator;
                    uniffi_bindgen::generate_bindings(
                        &udl_path,
                        config_file.as_deref(),
                        generator,
                        out_dir_override.as_deref(),
                        library_file.as_deref(),
                        crate_name.as_deref(),
                        format,
                    )?;
                }
                TargetLanguage::Swift => {
                    let generator = SwiftBindingGenerator;
                    uniffi_bindgen::generate_bindings(
                        &udl_path,
                        config_file.as_deref(),
                        generator,
                        out_dir_override.as_deref(),
                        library_file.as_deref(),
                        crate_name.as_deref(),
                        format,
                    )?;
                }
                TargetLanguage::Python => {
                    let generator = PythonBindingGenerator;
                    uniffi_bindgen::generate_bindings(
                        &udl_path,
                        config_file.as_deref(),
                        generator,
                        out_dir_override.as_deref(),
                        library_file.as_deref(),
                        crate_name.as_deref(),
                        format,
                    )?;
                }
            }

            let out = out_dir_override
                .map(|p| p.to_string())
                .unwrap_or_else(|| "当前目录".into());
            println!("✓ {lang} 绑定代码已生成到 {out}");
        }
    }

    // 避免未使用警告（PathBuf 在未来扩展中使用）
    let _ = PathBuf::new();

    Ok(())
}

impl std::fmt::Display for TargetLanguage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Kotlin => write!(f, "Kotlin"),
            Self::Swift => write!(f, "Swift"),
            Self::Python => write!(f, "Python"),
        }
    }
}
