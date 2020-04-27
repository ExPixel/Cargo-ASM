use clap::{App, Arg};
use std::path::PathBuf;

#[derive(Debug)]
pub struct AppArgs {
    pub binary_path: PathBuf,
    pub needle: String,
}

/// Parses arguments from the command line and returns them as an `AppArgs` struct.
pub fn parse_cli_args() -> AppArgs {
    let matches = App::new("Cargo ASM")
        .version("0.0.1")
        .author("Adolph C. <adolphc@outloook.com>")
        .arg(
            Arg::with_name("BINARY")
                .help("The binary to disassemble")
                .required(true)
                .index(1),
        )
        .arg(
            Arg::with_name("SEARCH")
                .help("The string to search for in a symbol name")
                .required(true)
                .index(2),
        )
        .get_matches();

    let binary_path = PathBuf::from(matches.value_of("BINARY").unwrap());
    let needle = matches.value_of("SEARCH").unwrap().to_string();

    AppArgs {
        binary_path,
        needle,
    }
}
