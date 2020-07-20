#[macro_use]
extern crate log;

use std::{env, process};
use std::fs;
use std::path::{Path, PathBuf};
use serde::{Serialize};
use snafu::{ResultExt};
use error::SettingsApplierError;

const DEFAULT_API_SOCKET: &str = "/run/api.sock";
const DEFAULT_ECS_CONFIG_PATH: &str = "/etc/ecs/ecs.config.json";
const VARIANT_ATTRIBUTE_NAME: &str = "bottlerocket.variant";
const VERSION_ATTRIBUTE_NAME: &str = "bottlerocket.version";


#[derive(Serialize, Debug)]
#[serde(rename_all="PascalCase")]
struct ECSConfig {
    #[serde(skip_serializing_if = "Option::is_none")]
    cluster: Option<String>,

    #[serde(skip_serializing_if = "std::collections::HashMap::is_empty")]
    instance_attributes: std::collections::HashMap<String, String>,
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
    let args = parse_args(env::args());

    // Get all settings values for config file templates
    debug!("Requesting settings values");
    let settings = schnauzer::get_settings(&args.socket_path).context(error::SettingsError)?;

    debug!("settings = {:#?}", settings.settings);
    let mut config = ECSConfig{
        cluster: settings.settings.and_then(|s| s.ecs).and_then(|s| s.cluster),
        instance_attributes: std::collections::HashMap::new()
    };
    match settings.os {
        None => {}
        Some(os) => {
            config.instance_attributes.insert(VARIANT_ATTRIBUTE_NAME.to_string(), os.variant_id);
            config.instance_attributes.insert(VERSION_ATTRIBUTE_NAME.to_string(), os.version_id.to_string());
        }
    }
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

// Stores user-supplied arguments.
struct Args {
    socket_path: String
}

fn parse_args(args: env::Args) -> Args {
    let mut socket_path = None;
    let mut iter = args.skip(1);
    while let Some(arg) = iter.next() {
        match arg.as_ref() {
            "--socket-path" => {
                socket_path = Some(
                    iter.next()
                        .unwrap_or_else(|| usage_msg("Did not give argument to --socket-path")),
                )
            }
            _ => usage(),
        }
    }
    Args {
        socket_path: socket_path.unwrap_or_else(|| DEFAULT_API_SOCKET.to_string()),
    }
}

// Prints a more specific message before exiting through usage().
fn usage_msg<S: AsRef<str>>(msg: S) -> ! {
    eprintln!("{}\n", msg.as_ref());
    usage();
}

// Informs the user about proper usage of the program and exits.
fn usage() -> ! {
    let program_name = env::args().next().unwrap_or_else(|| "program".to_string());
    eprintln!(
        r"Usage: {}
            [ (-s | --socket-path) PATH ]

    Socket path defaults to {}",
        program_name, DEFAULT_API_SOCKET
    );
    process::exit(2);
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
