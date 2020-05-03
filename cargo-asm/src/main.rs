mod arch;
mod binary;
mod cli;
mod disasm;
mod errors;
mod format;

use anyhow::Context;
use cli::{CliCommand, DisasmArgs, ListArgs};
use disasm::DisasmConfig;

fn main() {
    if let Err(err) = run() {
        eprintln!("error: {:?}", err);
        std::process::exit(1);
    }
}

fn run() -> anyhow::Result<()> {
    match cli::parse_cli_args() {
        CliCommand::Disasm(args) => run_command_disasm(args),
        CliCommand::List(args) => run_command_list(args),
    }
}

fn run_command_list(args: ListArgs) -> anyhow::Result<()> {
    use binary::analyze_binary;

    let binary_path = if let Some(ref path) = args.binary_path {
        path
    } else {
        // FIXME use cargo metadata to find binary path.
        eprintln!("no binary specified");
        std::process::exit(1);
    };

    let binary = std::fs::read(binary_path).with_context(|| {
        format!(
            "failed to read file `{}`",
            binary_path.as_path().to_string_lossy()
        )
    })?;

    let binary_info = analyze_binary(&binary)?;
    let matcher = disasm::SymbolMatcher::new(&args.needle);

    // First we do a measure step:
    let mut max_addr_len = 0;
    let mut max_size_len = 0;
    for symbol in binary_info
        .symbols
        .iter()
        .filter(|sym| matcher.matches(&sym.demangled_name))
    {
        max_addr_len = std::cmp::max(max_addr_len, format::addr_len(symbol.addr));
        max_size_len = std::cmp::max(max_size_len, format::off_len(symbol.size));
    }

    // Then we output:
    for symbol in binary_info
        .symbols
        .iter()
        .filter(|sym| matcher.matches(&sym.demangled_name))
    {
        println!(
            "[address: 0x{:0addr_width$X}] [size: {:size_width$} bytes] {}",
            symbol.addr,
            symbol.size,
            symbol.demangled_name,
            addr_width = max_addr_len,
            size_width = max_size_len,
        );
    }

    Ok(())
}

fn run_command_disasm(args: DisasmArgs) -> anyhow::Result<()> {
    let mut stdout = std::io::stdout();

    let binary_path = if let Some(ref path) = args.binary_path {
        path
    } else {
        // FIXME use cargo metadata to find binary path.
        eprintln!("no binary specified");
        std::process::exit(1);
    };

    let binary = std::fs::read(binary_path).with_context(|| {
        format!(
            "failed to read file `{}`",
            binary_path.as_path().to_string_lossy()
        )
    })?;

    let mut config = DisasmConfig::default();
    config.sym_output.display_address = !args.hide_address;
    config.sym_output.display_bytes = !args.hide_bytes;
    config.sym_output.display_jumps = !args.hide_jumps;
    config.sym_output.display_instr = true;
    config.display_length = true;
    config.display_instr_count = true;

    disasm::disassemble_binary(
        &binary,
        disasm::SymbolMatcher::new(&args.needle),
        &mut stdout,
        &config,
    )?;

    Ok(())
}
