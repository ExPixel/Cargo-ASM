#[derive(Clone, Debug)]
pub enum CargoAsmError {
    NoSymbolMatch(String),
    UnsupportedBinaryFormat(/* format */ &'static str),
    UnsupportedBinaryFormatOp(
        /* format */ &'static str,
        /* operation */ &'static str,
    ),
    NoCargoBinary,
}

impl std::error::Error for CargoAsmError {}

impl std::fmt::Display for CargoAsmError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match *self {
            CargoAsmError::NoSymbolMatch(ref search_string) => {
                write!(f, "no symbol matched the search string `{}`", search_string)
            }

            CargoAsmError::UnsupportedBinaryFormat(ref format) => {
                write!(f, "binary format `{}` not supported", format)
            }

            CargoAsmError::UnsupportedBinaryFormatOp(ref format, ref operation) => {
                if operation.is_empty() {
                    write!(f, "binary format `{}` not supported", format)
                } else {
                    write!(
                        f,
                        "operation `{}` not supported for `{}` binary format",
                        operation, format
                    )
                }
            }

            CargoAsmError::NoCargoBinary => write!(f, "no cargo binary found"),
        }
    }
}

#[derive(Debug)]
pub struct WCapstoneError(pub capstone::Error);

impl std::error::Error for WCapstoneError {}

impl std::fmt::Display for WCapstoneError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}
