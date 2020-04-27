#[derive(Debug)]
pub struct WCapstoneError(pub capstone::Error);

impl std::error::Error for WCapstoneError {}

impl std::fmt::Display for WCapstoneError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}
