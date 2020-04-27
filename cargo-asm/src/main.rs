mod arch;
mod binary;
mod cli;
mod disasm;
mod errors;
mod format;

fn main() {
    let args = cli::parse_cli_args();

    println!(
        "disassembling {}",
        args.binary_path.as_path().to_string_lossy()
    );

    let mut stdout = std::io::stdout();

    let binary = std::fs::read(&args.binary_path).expect("failed to read binary");
    disasm::disassemble_binary(
        &binary,
        disasm::SymbolMatcher::new(&[&args.needle]),
        &mut stdout,
    )
    .expect("failed to disassemble binary");
}
