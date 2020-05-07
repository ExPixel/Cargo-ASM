use clap::{App, AppSettings, Arg, ArgMatches, SubCommand};
use std::borrow::Cow;
use std::path::PathBuf;

#[derive(Debug)]
pub enum CliCommand {
    Disasm(DisasmArgs),
    List(ListArgs),
}

#[derive(Debug)]
pub struct ListArgs {
    pub binary_path: Option<PathBuf>,
    pub needle: String,

    pub cargo: CargoArgs,
}

#[derive(Debug)]
pub struct DisasmArgs {
    pub binary_path: Option<PathBuf>,
    pub needle: String,
    pub show_jumps: bool,
    pub show_bytes: bool,
    pub show_addrs: bool,
    pub show_source: bool,
    pub cargo: CargoArgs,
}

#[derive(Debug)]
pub struct CargoArgs {
    pub manifest_path: Option<PathBuf>,
    pub profile: Option<Cow<'static, str>>,
}

/// Parses arguments from the command line and returns them as an `AppArgs` struct.
pub fn parse_cli_args() -> CliCommand {
    let matches = App::new("Cargo ASM")
        .version("0.0.1")
        .author("Adolph C. <adolphc@outloook.com>")
        .setting(AppSettings::SubcommandRequired)
        .subcommand(
            SubCommand::with_name("disasm")
                .about("Disassembles the contents of a symbol in a binary.")
                .arg(
                    Arg::with_name("binary")
                        .short("b")
                        .long("binary")
                        .takes_value(true)
                        .value_name("BINARY")
                        .help("Path of a binary to disassemble and search for symbols in."),
                )
                .arg(
                    Arg::with_name("jumps")
                        .short("J")
                        .long("jumps")
                        .help("Jump jump arrows."),
                )
                .arg(
                    Arg::with_name("bytes")
                        .short("B")
                        .long("bytes")
                        .help("Show raw instruction bytes."),
                )
                .arg(
                    Arg::with_name("show-source")
                        .short("S")
                        .long("source")
                        .help("Show source code intermixed with assembly if possible."),
                )
                .arg(
                    Arg::with_name("no-addr")
                        .short("A")
                        .long("no-addr")
                        .help("Don't show the address of instructions."),
                )
                .arg(
                    Arg::with_name("release")
                        .long("release")
                        .help("Use the release binary built by Cargo."),
                )
                .arg(
                    Arg::with_name("manifest-path")
                        .long("manifest-path")
                        .takes_value(true)
                        .help("Path to Cargo.toml"),
                )
                .arg(
                    Arg::with_name("SEARCH")
                        .help("The string to search for in a symbol name")
                        .required(true)
                        .index(1),
                ),
        )
        .subcommand(
            SubCommand::with_name("list")
                .about("Lists the symbols contained inside of a binary.")
                .arg(
                    Arg::with_name("binary")
                        .short("b")
                        .long("binary")
                        .takes_value(true)
                        .value_name("BINARY")
                        .help("Path of a binary to disassemble and search for symbols in."),
                )
                .arg(
                    Arg::with_name("release")
                        .long("release")
                        .help("Use the release binary built by Cargo."),
                )
                .arg(
                    Arg::with_name("manifest-path")
                        .long("manifest-path")
                        .takes_value(true)
                        .help("Path to Cargo.toml"),
                )
                .arg(
                    Arg::with_name("FILTER")
                        .help("The filter used for the symbol names.")
                        .required(true)
                        .index(1),
                ),
        )
        .get_matches();

    if let Some(matches) = matches.subcommand_matches("disasm") {
        let binary_path = matches.value_of("binary").map(path_arg);
        let needle = matches.value_of("SEARCH").unwrap().to_string();
        let cargo = get_cargo_args(&matches);

        return CliCommand::Disasm(DisasmArgs {
            binary_path,
            needle,
            cargo,

            show_addrs: !matches.is_present("no-addr"),
            show_jumps: matches.is_present("jumps"),
            show_bytes: matches.is_present("bytes"),
            show_source: matches.is_present("show-source"),
        });
    }

    if let Some(matches) = matches.subcommand_matches("list") {
        let binary_path = matches.value_of("binary").map(path_arg);
        let needle = matches.value_of("FILTER").unwrap().to_string();
        let cargo = get_cargo_args(&matches);

        return CliCommand::List(ListArgs {
            binary_path,
            needle,
            cargo,
        });
    }

    std::process::exit(1);
}

fn get_cargo_args(matches: &ArgMatches) -> CargoArgs {
    let profile = if matches.is_present("release") {
        Some(Cow::from("release"))
    } else {
        None
    };

    let manifest_path = matches.value_of("manifest-path").map(path_arg);

    CargoArgs {
        profile,
        manifest_path,
    }
}

fn path_arg(arg_str: &str) -> PathBuf {
    PathBuf::from(&shellexpand::tilde(arg_str) as &str)
}
