#[macro_use]
extern crate log;

use std::{process};
use std::fs;
use std::path::{Path, PathBuf};
use serde::{Serialize};
use snafu::{ResultExt};
use error::SettingsApplierError;

// FIXME Get from configuration in the future
const DEFAULT_API_SOCKET: &str = "/run/api.sock";

const DEFAULT_ECS_CONFIG_PATH: &str = "/etc/ecs/ecs.config.json";


#[derive(Serialize, Debug)]
#[serde(rename_all="PascalCase")]
struct ECSConfig {
    #[serde(skip_serializing_if = "Option::is_none")]
    cluster: Option<String>,
}

// Returning a Result from main makes it print a Debug representation of the error, but with Snafu
// we have nice Display representations of the error, so we wrap "main" (run) and print any error.
// https://github.com/shepmaster/snafu/issues/110
fn main() {
    if let Err(e) = run() {
        eprintln!("{}", e);
        process::exit(1);
    }
}

fn run() -> Result<()> {
    // Get all settings values for config file templates
    debug!("Requesting settings values");
    let settings = schnauzer::get_settings(&DEFAULT_API_SOCKET).context(error::SettingsError)?;

    debug!("settings = {:#?}", settings.settings);
    let config = ECSConfig{ cluster: settings.settings.and_then(|s| s.ecs).and_then(|s| s.cluster)};
    let serialized = serde_json::to_string(&config).unwrap();
    debug!("serialized = {}", serialized);

    let config_path = PathBuf::from(DEFAULT_ECS_CONFIG_PATH);
    write_to_disk(config_path, serialized).context(error::FSError{path:DEFAULT_ECS_CONFIG_PATH})?;
    Ok(())
}

/// Writes the rendered data at the proper location
fn write_to_disk<P: AsRef<Path>, C: AsRef<[u8]>>(path: P, contents: C) -> std::io::Result<()> {
    if let Some(dirname) = path.as_ref().parent() {
        fs::create_dir_all(dirname)?;
    };

    fs::write(path, contents).map(|_| ())
}

type Result<T> = std::result::Result<T, SettingsApplierError>;

mod error {
    use snafu::Snafu;

    #[derive(Debug, Snafu)]
    #[snafu(visibility = "pub(super)")]
    pub(super) enum SettingsApplierError {
        #[snafu(display("Failed to read settings: {}", source))]
        SettingsError{
            source: schnauzer::Error
        },

        #[snafu(display("Filesystem operation for path {} failed: {}", path, source))]
        FSError{
            path: &'static str,
            source: std::io::Error
        }
    }
}
