mod arch;
mod binary;
mod cli;
mod disasm;
mod errors;
mod format;

use anyhow::Context;
use disasm::DisasmConfig;

fn main() {
    if let Err(err) = run() {
        eprintln!("error: {:?}", err);
        std::process::exit(1);
    }
}

fn run() -> anyhow::Result<()> {
    let args = cli::parse_cli_args();

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
