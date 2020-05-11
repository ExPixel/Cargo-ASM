mod arch;
mod binary;
mod cli;
mod disasm;
mod errors;
mod line_cache;
mod platform;

use anyhow::Context;
use binary::{Binary, FileResolveStrategy};
use cli::{CargoArgs, CliCommand, DisasmArgs, ListArgs};
use disasm::{DisasmConfig, DisasmContext};
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
    let binary_path = if let Some(ref path) = args.binary_path {
        std::borrow::Cow::from(path)
    } else {
        std::borrow::Cow::from(get_cargo_binary_path(&args.cargo)?)
    };

    let binary_data = std::fs::read(&binary_path)
        .with_context(|| format!("failed to read file `{}`", binary_path.to_string_lossy()))?;

    let binary = Binary::load(&binary_data, &binary_path, false)?;
    let matcher = disasm::SymbolMatcher::new(&args.needle);

    // First we do a measure step:
    let mut max_addr_len = 0;
    let mut max_size_len = 0;
    let mut matched_any_symbols = false;
    for symbol in binary
        .symbols
        .iter()
        .filter(|sym| matcher.matches(&sym.demangled_name))
    {
        matched_any_symbols = true;

        max_addr_len = std::cmp::max(max_addr_len, disasm::format::addr_len(symbol.addr));
        max_size_len = std::cmp::max(max_size_len, disasm::format::off_len(symbol.size));
    }

    if !matched_any_symbols {
        return Err(CargoAsmError::NoSymbolMatch(matcher.needle().to_string()).into());
    }

    // Then we output:
    for symbol in binary
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
    let source_root: PathBuf; // derived source root, can be overriden by option.
    let binary_path;
    if let Some(ref path) = args.binary_path {
        source_root = path
            .parent()
            .map(PathBuf::from)
            .unwrap_or(std::env::current_dir().context("failed to get current working directory")?);
        binary_path = std::borrow::Cow::from(path);
    } else {
        source_root = args
            .cargo
            .manifest_path
            .as_ref()
            .and_then(|p| p.parent())
            .map(PathBuf::from)
            .unwrap_or(std::env::current_dir().context("failed to get current working directory")?);
        binary_path = std::borrow::Cow::from(get_cargo_binary_path(&args.cargo)?);
    };

    let binary_data = std::fs::read(&binary_path)
        .with_context(|| format!("failed to read file `{}`", binary_path.to_string_lossy()))?;

    let binary = Binary::load(&binary_data, &binary_path, args.show_source)?;
    let matcher = disasm::SymbolMatcher::new(&args.needle);

    let mut config = DisasmConfig::default();
    config.display_address = args.show_addrs;
    config.display_bytes = args.show_bytes;
    config.display_jumps = args.show_jumps;
    config.display_patches = true;
    config.display_instr = true;
    config.display_source = args.show_source;
    config.load_debug_info = args.show_source;
    config.source_base_directory = args.source_root.unwrap_or(source_root);
    config.source_file_resolve = if args.absolute_source_path {
        FileResolveStrategy::PreferAbsolute
    } else {
        FileResolveStrategy::PreferRelative
    };

    // FIXME implement these. Shows how many bytes of assembly are in the function and the number
    //       of instructions.
    config.display_length = true;
    config.display_instr_count = true;

    let matched_symbol = binary
        .symbols
        .iter()
        .find(|sym| matcher.matches(&sym.demangled_name))
        .ok_or_else(|| CargoAsmError::NoSymbolMatch(matcher.needle().to_string()))?;
    let mut context = DisasmContext::new(config, &binary)?;
    let mut stdout = std::io::stdout();
    disasm::disassemble(matched_symbol, &mut context, &mut stdout)?;

    Ok(())
}

fn get_cargo_binary_path(cargo_args: &CargoArgs) -> anyhow::Result<PathBuf> {
    use cargo_metadata::Target;

    let mut cmd = cargo_metadata::MetadataCommand::new();
    cmd.no_deps();
    cmd.other_options(&["--offline".to_string()] as &[String]);

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
