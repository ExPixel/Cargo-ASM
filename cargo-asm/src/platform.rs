use std::borrow::Cow;
use std::path::{Path, PathBuf};

pub trait PathConverter {
    fn is_relative(&self, path_str: &str) -> bool;
    fn convert<'s>(&self, path_str: &'s str) -> Cow<'s, Path>;
}

struct WindowsToUnixPathConverter;
struct UnixToWindowsPathConverter;
pub struct NativePathConverter;

impl PathConverter for NativePathConverter {
    fn is_relative<'s>(&self, path_str: &str) -> bool {
        Path::new(path_str).is_relative()
    }

    fn convert<'s>(&self, path_str: &'s str) -> Cow<'s, Path> {
        Cow::from(Path::new(path_str))
    }
}

impl PathConverter for WindowsToUnixPathConverter {
    fn is_relative<'s>(&self, path_str: &str) -> bool {
        let mut chars = path_str.chars();

        // Parsing DriveLetter:/ or DriveLetter:\

        if let Some(ch) = chars.next() {
            if !ch.is_alphabetic() {
                return true;
            }
        }

        let mut colon = false;
        while let Some(ch) = chars.next() {
            if ch == ':' {
                colon = true;
                break;
            } else if !ch.is_alphabetic() {
                return true;
            }
        }

        if !colon {
            return true;
        }

        let slash = chars.next();
        if slash != Some('/') && slash != Some('\\') {
            return true;
        }

        false
    }

    fn convert<'s>(&self, path_str: &'s str) -> Cow<'s, Path> {
        // FIXME Implement converting windows paths to unix paths.
        //       Should probably replace the drive with the root directory.
        if path_str.contains('\\') {
            Cow::from(PathBuf::from(path_str.replace('\\', "/")))
        } else {
            Cow::from(Path::new(path_str))
        }
    }
}

impl PathConverter for UnixToWindowsPathConverter {
    fn is_relative(&self, path_str: &str) -> bool {
        !path_str.starts_with('/')
    }

    fn convert<'s>(&self, path_str: &'s str) -> Cow<'s, Path> {
        // FIXME Implement converting unix paths to windows paths.
        //       Should probably replace the root directory with the drive of the
        //       base directory.
        if path_str.contains('/') {
            Cow::from(PathBuf::from(path_str.replace('/', "\\")))
        } else {
            Cow::from(Path::new(path_str))
        }
    }
}

#[derive(Copy, Clone, PartialEq, Eq)]
pub enum Platform {
    Windows,
    Unix,
}

/// Returns a path converter that will convert from the given platform's path to the native
/// platform's path.
pub fn path_converter_from(platform: Platform) -> Box<dyn 'static + PathConverter> {
    match platform {
        Platform::Windows => {
            if cfg!(target_os = "windows") {
                Box::new(NativePathConverter)
            } else {
                Box::new(WindowsToUnixPathConverter)
            }
        }

        Platform::Unix => {
            if cfg!(target_os = "windows") {
                Box::new(UnixToWindowsPathConverter)
            } else {
                Box::new(NativePathConverter)
            }
        }
    }
}
