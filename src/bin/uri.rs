//! `shadowvpn-uri` — import/export a client config as a `shadowvpn://` URI or QR
//! code.
//!
//! A standalone tool so the server/client binaries stay lean: it is built only
//! with `--features uri`, which pulls in the QR/image dependencies. See
//! [`shadowvpn::uri`] for the URI format.
//!
//! ```text
//! shadowvpn-uri export -c client.json [--qr]
//! shadowvpn-uri import 'shadowvpn://…' -o client.json
//! shadowvpn-uri import --image qr.png -o client.json
//! ```

use std::path::PathBuf;

use anyhow::{bail, Context, Result};
use clap::{Parser, Subcommand};

use shadowvpn::config::FileConfig;
use shadowvpn::uri;

#[derive(Parser)]
#[command(
    name = "shadowvpn-uri",
    about = "Import/export a ShadowVPN client config as a shadowvpn:// URI or QR code."
)]
struct Cli {
    #[command(subcommand)]
    action: Action,
}

#[derive(Subcommand)]
enum Action {
    /// Encode a JSON config file as a `shadowvpn://` URI (optionally a QR code).
    Export {
        /// Path to the JSON client config to export.
        #[arg(short = 'c', long = "config")]
        config: PathBuf,
        /// Also render a scannable QR code to the terminal.
        #[arg(long)]
        qr: bool,
    },
    /// Decode a `shadowvpn://` URI (or a QR image) into a JSON config file.
    Import {
        /// The `shadowvpn://` URI. Omit when using `--image`.
        uri: Option<String>,
        /// Read the URI from a QR-code image (PNG/JPEG) instead of an argument.
        #[arg(long, value_name = "FILE")]
        image: Option<PathBuf>,
        /// Write the JSON config here (default: stdout).
        #[arg(short = 'o', long = "out")]
        out: Option<PathBuf>,
    },
}

fn main() -> Result<()> {
    match Cli::parse().action {
        Action::Export { config, qr } => {
            let file = FileConfig::load(&config)
                .with_context(|| format!("loading config {}", config.display()))?;
            let encoded = uri::encode(&file);
            println!("{encoded}");
            if qr {
                let rendered = uri::render_qr(&encoded).context("rendering QR code")?;
                println!("\n{rendered}");
            }
            Ok(())
        }
        Action::Import { uri, image, out } => {
            let text = match (uri, image) {
                (Some(_), Some(_)) => bail!("provide either a URI argument or --image, not both"),
                (None, None) => bail!("provide a shadowvpn:// URI argument or --image <FILE>"),
                (Some(s), None) => s,
                (None, Some(path)) => uri::decode_qr_image(&path)
                    .with_context(|| format!("decoding QR code from {}", path.display()))?,
            };
            let file = uri::decode(&text).context("decoding shadowvpn:// URI")?;
            let json = serde_json::to_string_pretty(&file).context("serializing config to JSON")?;
            match out {
                Some(path) => {
                    std::fs::write(&path, format!("{json}\n"))
                        .with_context(|| format!("writing {}", path.display()))?;
                    eprintln!("wrote config to {}", path.display());
                }
                None => println!("{json}"),
            }
            Ok(())
        }
    }
}
