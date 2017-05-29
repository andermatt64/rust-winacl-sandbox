extern crate clap;
extern crate env_logger;
extern crate log;
extern crate mio;
extern crate winapi;

include!(concat!(env!("OUT_DIR"), "/version.rs"));

#[cfg(windows)]
mod acl;
mod appcontainer;
mod winffi;

#[cfg(not(test))]
use mio::*;

#[cfg(not(test))]
use winffi::GENERIC_READ;

#[cfg(not(test))]
use mio::tcp::TcpListener;

#[cfg(not(test))]
use std::process;

#[cfg(all(not(test), windows))]
use std::os::windows::io::AsRawSocket;

#[cfg(not(test))]
use std::path::{Path, PathBuf};

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
fn add_sid_profile_entry(path: &Path, sid: &str) -> bool {
    // NOTE: Will this mess up for special unicode paths?
    let result = acl::SimpleDacl::from_path(path.to_str().unwrap());
    if let Err(x) = result {
        error!("Failed to get ACL from {:?}: error={:}", path, x);
        return false;
    }

    let mut dacl = result.unwrap();

    if dacl.entry_exists(sid, acl::ACCESS_ALLOWED).is_some() {
        if !dacl.remove_entry(sid, acl::ACCESS_ALLOWED) {
            error!("Failed to remove existing ACL entry for AppContainer SID");
            return false;
        }
    }

    if !dacl.add_entry(acl::AccessControlEntry {
                           entryType: acl::ACCESS_ALLOWED,
                           flags: 0,
                           mask: GENERIC_READ,
                           sid: sid.to_string(),
                       }) {
        error!("Failed to add AppContainer profile ACL entry from {:?}",
               path);
        return false;
    }

    match dacl.apply_to_path(path.to_str().unwrap()) {
        Ok(_) => {
            info!("  Added ACL entry for AppContainer profile in {:?}", path);
        }
        Err(x) => {
            error!("Failed to set new ACL into {:?}: error={:}", path, x);
            return false;
        }
    }

    true
}

#[cfg(all(windows, not(test)))]
#[allow(unreachable_code)]
fn do_run(matches: &ArgMatches) {
    let key_path = PathBuf::from(matches.value_of("key").unwrap());
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

    let addr: &str = &format!("{}:{}",
                              matches.value_of("host").unwrap(),
                              matches.value_of("port").unwrap());
    info!("  tcp server addr = {:?}", addr);

    let profile_name = matches.value_of("name").unwrap();
    info!("  profile name = {:?}", profile_name);

    // NOTE: Will special unicode paths mess up this unwrap()?
    let mut profile = match appcontainer::Profile::new(profile_name,
                                                       child_path.to_str().unwrap()) {
        Ok(x) => x,
        Err(x) => {
            error!("Failed to create AppContainer profile for {:}: error={:}",
                   profile_name,
                   x);
            process::exit(-1);
        }
    };
    info!("profile name = {:}, sid = {:}", profile_name, profile.sid);

    profile.enable_outbound_network(matches.is_present("outbound"));
    info!("AppContainer.enable_outbound_network_conn = {:}",
          matches.is_present("outbound"));

    profile.enable_debug(matches.is_present("debug"));
    info!("AppContainer.enable_debug = {:}",
          matches.is_present("debug"));

    let mut key_dir_path = key_path.clone();
    key_dir_path.pop();

    if !add_sid_profile_entry(&key_dir_path, &profile.sid) {
        error!("Failed to add AppContainer profile ACL entry into {:?}",
               key_dir_path);
        process::exit(-1);
    }

    if !add_sid_profile_entry(&key_path, &profile.sid) {
        error!("Failed to add AppContainer profile ACL entry into {:?}",
               key_path);
        process::exit(-1);
    }

    {
        const SERVER: Token = Token(0);

        let server_addr = match addr.parse() {
            Ok(x) => x,
            Err(_) => {
                error!("Invalid socket address \"{:}\"", addr);
                process::exit(-1);
            }
        };
        let server = match TcpListener::bind(&server_addr) {
            Ok(x) => x,
            Err(_) => {
                error!("Failed to bind server socket on {:}", addr);
                process::exit(-1);
            }
        };

        let poll = match Poll::new() {
            Ok(x) => x,
            Err(_) => {
                error!("Failed to create poll");
                process::exit(-1);
            }
        };

        if let Err(_) = poll.register(&server, SERVER, Ready::readable(), PollOpt::edge()) {
            error!("Failed to register server socket into poll");
            process::exit(-1);
        }

        let mut events = Events::with_capacity(1024);
        info!("Entering event loop");
        println!("Listening on {:} for new requests...", addr);

        loop {
            if let Err(_) = poll.poll(&mut events, None) {
                error!("Poll failed");
                process::exit(-1);
            }

            for event in events.iter() {
                match event.token() {
                    SERVER => {
                        if let Ok((client_sock, client_addr)) = server.accept() {
                            println!(" => New connection from {:?}", client_addr);
                            info!("  => Connection socket {:08x} from {:?}",
                                  client_sock.as_raw_socket(),
                                  client_addr);

                            // NOTE: Watch out for the unwrap()
                            // FIXME: We need to convert client_sock into a WSASocket somehow...
                            match profile.launch(client_sock.as_raw_socket(),
                                                 key_dir_path.to_str().unwrap()) {
                                Ok(x) => {
                                    info!("     Launched new process with handle {:?}", x.raw);
                                }
                                Err(x) => {
                                    error!("     Failed to launch new process: error={:}", x);
                                }
                            }
                        }
                    }
                    _ => unreachable!(),
                }
            }
        }

        process::exit(0);
    }
}

#[cfg(all(windows, not(test)))]
fn remove_sid_acl_entry(path: &Path, sid: &str) -> bool {
    // NOTE: Will this mess up for special unicode paths?
    let result = acl::SimpleDacl::from_path(path.to_str().unwrap());
    if let Err(x) = result {
        error!("Failed to get ACL from {:?}: error={:}", path, x);
        return false;
    }

    let mut dacl = result.unwrap();

    if !dacl.remove_entry(sid, acl::ACCESS_ALLOWED) {
        error!("Failed to remove AppContainer profile ACL entry from {:?}",
               path);
        return false;
    }

    match dacl.apply_to_path(path.to_str().unwrap()) {
        Ok(_) => {
            info!("  Removed ACL entry for AppContainer profile in {:?}", path);
        }
        Err(x) => {
            error!("Failed to set new ACL into {:?}: error={:}", path, x);
            return false;
        }
    }

    true
}

#[cfg(all(windows, not(test)))]
fn do_clean(matches: &ArgMatches) {
    let profile_name = matches.value_of("profile").unwrap();
    println!("Removing AppContainer profile \"{:}\"", profile_name);

    if let Some(raw_key_path) = matches.value_of("key") {
        let key_path = PathBuf::from(raw_key_path);
        let mut key_dir_path = key_path.clone();
        key_dir_path.pop();

        info!("  key_path = {:?}", key_path);
        info!("  key_dir_path = {:?}", key_dir_path);

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

        if !remove_sid_acl_entry(&key_path, &profile.sid) {
            error!("Failed to remove entry for key_path={:?}", key_path);
        }

        if !remove_sid_acl_entry(&key_dir_path, &profile.sid) {
            error!("Failed to remove entry for key_dir_path={:?}", key_dir_path);
        }
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
