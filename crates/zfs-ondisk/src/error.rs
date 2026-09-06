//! Error type shared by all parsers.

use std::fmt;

/// Why a byte slice could not be parsed as the requested structure.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ParseError {
    /// The slice is shorter than the structure requires.
    Truncated {
        /// Bytes required.
        needed: usize,
        /// Bytes available.
        got: usize,
    },
    /// The magic number does not match in either byte order.
    ///
    /// Carries the raw little-endian reading so callers can distinguish an
    /// all-zero (never written) slot from garbage.
    BadMagic(u64),
}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ParseError::Truncated { needed, got } => {
                write!(f, "truncated: need {needed} bytes, got {got}")
            }
            ParseError::BadMagic(0) => write!(f, "empty (magic is zero)"),
            ParseError::BadMagic(m) => write!(f, "bad magic {m:#018x}"),
        }
    }
}

impl std::error::Error for ParseError {}
