/// 0.95:1 xeBuild CLI clone
/// Functional parity, rebranded and outputs formatted

use std::ffi::OsString;
use std::path::PathBuf;

use clap::{arg, Arg, ArgAction, Command};
use crate::core::session::Session;

fn cli() -> Command {
    Command::new("ggxbuild")
        .about("xeBuild v1.21.810 clone - System image builder")
        .arg_required_else_help(true)
        .allow_external_subcommands(true)
        .args(build_args())
        .subcommand(
            Command::new("build")
                .about("Image Build Mode (Default)")
                .args(build_args()),
        )
        .subcommand(
            Command::new("extract")
                .about("Perform dump loading and verification for diagnostics")
        )
        .subcommand(
            Command::new("client")
                .about("Client mode - read, write and patch flash over network")
        )
        .subcommand(
            Command::new("update")
                .about("Update mode - update console patches and flash over network")
        )
}

fn build_args() -> Vec<Arg> {
    vec![
        arg!(-t --type <TYPE> "retail, jtag, glitch, glitch2, glitch2m, devkit")
            .default_value("retail")
            .value_parser(["retail", "jtag", "glitch", "glitch2", "glitch2m", "devkit"]),
        arg!(-p --cpukey <KEY> "32 character CPU hex key"),
        arg!(-b --blkey <KEY> "32 character 1BL hex key"),
        arg!(-c --console <CON> "Console type (e.g., xenon, zephyr, falcon, trinity, corona...)"),
        arg!(-d --datadir <DIR> "Per build files directory").value_parser(clap::value_parser!(PathBuf)),
        arg!(-f --fwdir <DIR> "Use different data dir and file lists").value_parser(clap::value_parser!(PathBuf)),
        arg!(-s --sha <FILE> "Outputs SHA-1 of final image to <file>").value_parser(clap::value_parser!(PathBuf)),
        arg!(-o --option <OPT> "Set xeBuild options (nomobile, noremap, etc)")
            .action(ArgAction::Append),
        arg!(-a --addon <NAME> "Append patches")
            .action(ArgAction::Append),
        arg!(-i --iniext <EXT> "Adds _<ext> into firmware ini and patches file names"),
        arg!(-r --blext <EXT> "Adds _<ext> into ini bl section name and patches file names"),
        Arg::new("rawpatch")
            .short('8')
            .long("rawpatch")
            .action(ArgAction::Append)
            .help("Adds raw patch to NAND just before finalizing"),
        arg!(-v --verbose "Shows more info during build process")
            .action(ArgAction::SetTrue),
        arg!(noenter: -n --noenter "Suppresses prompt for enter key when finished")
            .action(ArgAction::SetTrue),
        arg!([OUTPUT] "Optional, overrides auto built output image name")
            .value_parser(clap::value_parser!(PathBuf)),
    ]
}

pub fn ggx_cli() {
    let matches = cli().get_matches();
    let mut session = Session::new();

    // Check if a subcommand was used
    match matches.subcommand() {
        Some(("build", sub_matches)) => {
            handle_build(sub_matches, &mut session);
        }
        Some(("extract", _sub_matches)) => {
            session.extract_all(); // Just an example
        }
        Some(("client", _sub_matches)) => {
            println!("Client mode selected. (Not fully wired to session yet)");
        }
        Some(("update", _sub_matches)) => {
            session.update();
        }
        Some((ext, _sub_matches)) => {
            println!("Calling out to external mode {ext:?}");
        }
        None => {
            // No subcommand matched, default to build mode with top-level matches
            handle_build(&matches, &mut session);
        }
    }

    if let Err(e) = session.run() {
        eprintln!("Session failed: {}", e);
    }
}

fn handle_build(matches: &clap::ArgMatches, session: &mut Session) {
    let build_type = matches.get_one::<String>("type").expect("defaulted");
    
    // Instead of immediately printing, we pass the command intent to the Session
    // For now, we'll configure the state if needed, and just enqueue the 'Build' logic
    
    // session.set_build_type(build_type);
    
    // E.g., setting global context options
    // let verbose = matches.get_flag("verbose");
    // session.set_verbose(verbose);

    session.build();
}