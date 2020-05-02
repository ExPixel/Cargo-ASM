#[derive(Clone, Debug)]
pub enum CargoAsmError {
    NoSymbolMatch(String),
}

impl std::error::Error for CargoAsmError {}

impl std::fmt::Display for CargoAsmError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match *self {
            CargoAsmError::NoSymbolMatch(ref search_string) => {
                write!(f, "no symbol matched the search string `{}`", search_string)
            }
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
