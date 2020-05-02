use clap::{App, Arg};
use std::path::PathBuf;

#[derive(Debug)]
pub struct AppArgs {
    pub binary_path: Option<PathBuf>,
    pub needle: String,

    pub hide_jumps: bool,
    pub hide_bytes: bool,
    pub hide_address: bool,
}

/// Parses arguments from the command line and returns them as an `AppArgs` struct.
pub fn parse_cli_args() -> AppArgs {
    let matches = App::new("Cargo ASM")
        .version("0.0.1")
        .author("Adolph C. <adolphc@outloook.com>")
        .arg(
            Arg::with_name("binary")
                .short("b")
                .long("binary")
                .takes_value(true)
                .value_name("BINARY")
                .help("Path of a binary to disassemble and search for symbols in."),
        )
        .arg(
            Arg::with_name("no-jumps")
                .long("no-jumps")
                .help("Don't show jumps."),
        )
        .arg(
            Arg::with_name("no-bytes")
                .long("no-bytes")
                .help("Don't show raw instruction bytes."),
        )
        .arg(
            Arg::with_name("no-addr")
                .long("no-addr")
                .help("Don't show the address of instructions."),
        )
        .arg(
            Arg::with_name("SEARCH")
                .help("The string to search for in a symbol name")
                .required(true)
                .index(1),
        )
        .get_matches();

    let binary_path = matches
        .value_of("binary")
        .map(|s| shellexpand::tilde(s))
        .map(|s| PathBuf::from(&s as &str));
    let needle = matches.value_of("SEARCH").unwrap().to_string();

    AppArgs {
        binary_path,
        needle,

        hide_address: matches.is_present("no-addr"),
        hide_jumps: matches.is_present("no-jumps"),
        hide_bytes: matches.is_present("no-bytes"),
    }
}
