mod arch;
mod binary;
mod cli;
mod disasm;
mod errors;
mod format;
mod line_cache;

use anyhow::Context;
use cli::{CargoArgs, CliCommand, DisasmArgs, ListArgs};
use disasm::DisasmConfig;
use errors::CargoAsmError;
use std::path::PathBuf;

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
        std::borrow::Cow::from(path)
    } else {
        std::borrow::Cow::from(get_cargo_binary_path(&args.cargo)?)
    };

    let binary = std::fs::read(&binary_path)
        .with_context(|| format!("failed to read file `{}`", binary_path.to_string_lossy()))?;

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
        std::borrow::Cow::from(path)
    } else {
        std::borrow::Cow::from(get_cargo_binary_path(&args.cargo)?)
    };

    let binary = std::fs::read(&binary_path)
        .with_context(|| format!("failed to read file `{}`", binary_path.to_string_lossy()))?;

    let mut config = DisasmConfig::default();
    config.sym_output.display_address = args.show_addrs;
    config.sym_output.display_bytes = args.show_bytes;
    config.sym_output.display_jumps = args.show_jumps;
    config.sym_output.display_patches = true;
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

fn get_cargo_binary_path(cargo_args: &CargoArgs) -> anyhow::Result<PathBuf> {
    use cargo_metadata::Target;

    let mut cmd = cargo_metadata::MetadataCommand::new();
    cmd.no_deps();
    cmd.other_options(&["--offline".to_string()]);

    if let Some(ref manifest_path) = cargo_args.manifest_path {
        cmd.manifest_path(manifest_path);
    }

    let metadata = cmd.exec()?;

    // A vec of targets with executables.
    let bin_targets = metadata
        .workspace_members
        .iter()
        .filter_map(|id| metadata.packages.iter().find(|pkg| pkg.id == *id))
        .flat_map(|pkg| pkg.targets.iter())
        .filter(|target| target.kind.iter().any(|k| k == "bin"))
        .collect::<Vec<&Target>>();

    if bin_targets.len() > 1 {
        eprintln!(
            "warning: more than one 'bin' target found, using {}.",
            bin_targets[0].name
        );
    } else if bin_targets.is_empty() {
        return Err(CargoAsmError::NoCargoBinary.into());
    }

    let mut binary_path = PathBuf::from(&metadata.target_directory);
    binary_path.push(
        &cargo_args
            .profile
            .as_ref()
            .map(|c| c as &str)
            .unwrap_or("debug"),
    );
    binary_path.push(&bin_targets[0].name);

    Ok(binary_path)
}
