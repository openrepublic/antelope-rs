use std::io::Write;

use flate2::{write::ZlibEncoder, Compression};
use hex::{decode, encode};

pub fn hex_to_bytes(hex: &str) -> Vec<u8> {
    decode(hex).unwrap()
}

pub fn bytes_to_hex(bytes: &Vec<u8>) -> String {
    encode(bytes)
}

pub fn array_equals<T: PartialEq>(a: &[T], b: &[T]) -> bool {
    a.len() == b.len() && a.iter().zip(b).all(|(x, y)| x == y)
}

pub fn array_to_hex(bytes: &[u8]) -> String {
    //bytes.iter().map(|b| format!("{:02x}", b)).collect()
    encode(bytes)
}

pub fn slice_copy(dst: &mut [u8], src: &[u8]) {
    dst.copy_from_slice(src);
    // assert!(dst.len() == src.len(), "copy_slice: length not the same!");
    // unsafe { memcpy(dst.as_mut_ptr(), src.as_ptr(), dst.len()); }
}

pub fn zlib_compress(bytes: &[u8]) -> Result<Vec<u8>, String> {
    let mut e = ZlibEncoder::new(Vec::new(), Compression::default());
    if e.write_all(bytes).is_err() {
        return Err("Error during compression".into());
    }
    let compressed_bytes = e.finish();
    if compressed_bytes.is_err() {
        return Err("Error during compression".into());
    }
    Ok(compressed_bytes.unwrap())
}

// backtrace capture -------------------------------------------
use std::backtrace::Backtrace;
use std::fmt::{Display, Formatter};
use std::error::Error as StdError;

/// A thin, zero‑cost*¹* wrapper that augments any `thiserror` (or
/// any other `std::error::Error`) with a captured backtrace.
///
/// ```text
/// Err(something)?          // propagates plain error
/// Err(something).bt()?     // propagates error + backtrace
/// ```
#[derive(Debug)]
pub struct Backtraced<E>
where
    E: StdError + Send + Sync + 'static,
{
    /// The original error – never modified.
    pub inner: E,

    /// Snapshot taken *at construction*.
    ///
    /// It is still shown only when RUST_BACKTRACE=1 (like any backtrace).
    pub backtrace: Backtrace,
}

// Constructors -------------------------------------------------
impl<E> Backtraced<E>
where
    E: StdError + Send + Sync + 'static,
{
    /// Wrap an existing error **without** changing its type.
    #[inline]
    pub fn new(inner: E) -> Self {
        Self { inner, backtrace: Backtrace::capture() }
    }

}

// `Display` and `Error` implementations -----------------------
impl<E> Display for Backtraced<E>
where
    E: StdError + Send + Sync + 'static,
{
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        Display::fmt(&self.inner, f)
    }
}

impl<E> StdError for Backtraced<E>
where
    E: StdError + Send + Sync + 'static,
{
    fn source(&self) -> Option<&(dyn StdError + 'static)> {
        Some(&self.inner)          // already handled by #[source], but explicit OK
    }

    // fn backtrace(&self) -> Option<&Backtrace> {
    //     Some(&self.backtrace)      // already handled by #[backtrace]
    // }
}

// Automatic `From<E>` -----------------------------------------
impl<E> From<E> for Backtraced<E>
where
    E: StdError + Send + Sync + 'static,
{
    #[inline]
    fn from(err: E) -> Self {
        Self::new(err)
    }
}
