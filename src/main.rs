extern crate clap;
extern crate env_logger;
extern crate log;

include!(concat!(env!("OUT_DIR"), "/version.rs"));

#[cfg(windows)]
mod acl;
mod appcontainer;
mod winffi;

#[cfg(not(test))]
use std::process;

#[cfg(not(test))]
use std::path::Path;

#[allow(unused_imports)]
use log::*;

#[cfg(not(test))]
use clap::{Arg, App, SubCommand, ArgMatches};

#[cfg(not(test))]
fn build_version() -> String {
    let prebuilt_ver = semver();
    if prebuilt_ver.len() == 0 {
        return format!("build-{} ({})", short_sha(), short_now());
    }

    format!("{}", prebuilt_ver)
}

#[cfg(all(windows, not(test)))]
fn do_run(matches: &ArgMatches) {
    let key_path = Path::new(matches.value_of("key").unwrap());
    info!("  key_path = {:?}", key_path);

    if !key_path.exists() || key_path.is_dir() || !key_path.is_file() {
        error!("Specified key path ({:?}) is invalid", key_path);
        process::exit(-1);
    }

    let child_path = Path::new(matches.value_of("CHILD_PATH").unwrap());
    info!("  child_path = {:?}", child_path);

    if !child_path.exists() || child_path.is_dir() || !child_path.is_file() {
        error!("Specified child path ({:?}) is invalid", child_path);
        process::exit(-1);
    }

    let addr = format!("{}:{}",
                       matches.value_of("host").unwrap(),
                       matches.value_of("port").unwrap());
    info!("  tcp server addr = {:?}", addr);

    let profile_name = matches.value_of("name").unwrap();
    info!("  profile name = {:?}", profile_name);

}

#[cfg(all(windows, not(test)))]
fn do_clean(matches: &ArgMatches) {
    let profile_name = matches.value_of("profile").unwrap();
    println!("Removing AppContainer profile \"{:}\"", profile_name);

    if let Some(raw_key_path) = matches.value_of("key") {
        let key_path = Path::new(raw_key_path);
        info!("  key_path = {:?}", key_path);

        if !key_path.exists() || key_path.is_dir() || !key_path.is_file() {
            error!("Specified key path ({:?}) is invalid", key_path);
            process::exit(-1);
        }

        // We create the profile_name with key_path as the child process in order
        // to get the AppContainer SID for profile_name
        let profile = match appcontainer::Profile::new(profile_name, key_path.to_str().unwrap()) {
            Ok(x) => x,
            Err(x) => {
                error!("Failed to get profile information for \"{:}\": error={:}",
                       profile_name,
                       x);
                process::exit(-1);
            }
        };

        // NOTE: Will this mess up with special unicode names?
        match acl::SimpleDacl::from_path(key_path.to_str().unwrap()) {
            Ok(mut dacl) => {
                if !dacl.remove_entry(&profile.sid) {
                    error!("Failed to remove AppContainer profile ACL entry from ACL!");
                } else {
                    // NOTE: Will this mess up with special unicode names?
                    match dacl.apply_to_path(key_path.to_str().unwrap()) {
                        Ok(_) => {
                            println!("  Removed ACL entry for AppContainer profile in {:?}",
                                     key_path);
                        }
                        Err(x) => {
                            error!("Failed to set new ACL into {:?}: error={:}", key_path, x);
                        }
                    };
                }
            }
            Err(x) => {
                error!("Failed to get ACL from {:?}: error={:}", key_path, x);
            }
        };
    }

    if !appcontainer::Profile::remove(profile_name) {
        error!("  Failed to remove \"{:}\" profile", profile_name);
    } else {
        println!("  SUCCESS - removed \"{:}\" profile", profile_name);
    }

    process::exit(0);
}

#[cfg(all(windows, not(test)))]
fn main() {
    let app_version: &str = &build_version();
    let matches = App::new("AppJailLauncher")
        .version(app_version)
        .author("author <email>")
        .about("A TCP server meant for spawning AppContainer'd client processes for Windows-based CTF challenges")
        .subcommand(SubCommand::with_name("run")
            .version(app_version)
            .about("Launch a TCP server")
            .arg(Arg::with_name("name")
                     .short("n")
                     .long("name")
                     .value_name("NAME")
                     .default_value("default_appjail_profile")
                     .help("AppContainer profile name"))
            .arg(Arg::with_name("debug")
                     .long("debug")
                     .help("Enable debug mode where the AppContainers are disabled"))
            .arg(Arg::with_name("outbound")
                     .long("enable-outbound")
                     .help("Enables outbound network connections from the AppContainer'd process"))
            .arg(Arg::with_name("key")
                     .short("k")
                     .long("key")
                     .value_name("KEYFILE")
                     .required(true)
                     .help("The path to the \"key\" file that contains the challenge solution token"))
            .arg(Arg::with_name("port")
                     .short("p")
                     .long("port")
                     .value_name("PORT")
                     .default_value("4444")
                     .help("Port to bind the TCP server on"))
            .arg(Arg::with_name("host")
                     .short("h")
                     .long("host")
                     .value_name("HOST")
                     .default_value("0.0.0.0")
                     .help("IP address to bind the TCP server on"))
            .arg(Arg::with_name("CHILD_PATH")
                     .index(1)
                     .required(true)
                     .help("Path to the child process to be AppContainer'd upon TCP client acceptance")))
        .subcommand(SubCommand::with_name("clean")
            .version(app_version)
            .about("Clean AppContainer profiles that have been created on the system")
            .arg(Arg::with_name("name")
                     .short("n")
                     .long("name")
                     .value_name("NAME")
                     .default_value("default_appjail_profile")
                     .help("AppContainer profile name")))
            .arg(Arg::with_name("key")
                     .short("k")
                     .long("key")
                     .value_name("KEYFILE")
                     .help("The path to the \"key\" file that contains the challenge solution token"))
        .get_matches();

    if let Err(_) = env_logger::init() {
        println!("FATAL: failed to initialize env_logger!");
        process::exit(-1);
    }

    if let Some(run_matches) = matches.subcommand_matches("run") {
        info!("Detected subcommand 'run'");
        do_run(run_matches);
    } else if let Some(clean_matches) = matches.subcommand_matches("clean") {
        info!("Detected subcommand 'clean");
        do_clean(clean_matches);
    } else {
        error!("No subcommand provided!");
        process::exit(1);
    }
}

#[cfg(not(windows))]
fn main() {
    println!("Build target is not supported!");
    process::exit(-1);
}
