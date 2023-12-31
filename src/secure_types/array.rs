use core::fmt;
use std::{
    borrow::{Borrow, BorrowMut},
    str::FromStr,
};

use zeroize::Zeroize;

use crate::secure_utils::memlock;

/// A data type suitable for storing sensitive information such as passwords and private keys in memory, that implements:
///
/// - Automatic zeroing in `Drop`
/// - Constant time comparison in `PartialEq` (does not short circuit on the first different character; but terminates instantly if strings have different length)
/// - Outputting `***SECRET***` to prevent leaking secrets into logs in `fmt::Debug` and `fmt::Display`
/// - Automatic `mlock` to protect against leaking into swap (any unix)
/// - Automatic `madvise(MADV_NOCORE/MADV_DONTDUMP)` to protect against leaking into core dumps (FreeBSD, DragonflyBSD, Linux)
///
/// Comparisons using the `PartialEq` implementation are undefined behavior (and most likely wrong) if `T` has any padding bytes.
#[derive(Eq, PartialEq, PartialOrd, Ord, Hash)]
pub struct SecureArray<T, const LENGTH: usize>
where
    T: Copy + Zeroize,
{
    pub(crate) content: [T; LENGTH],
}

impl<T, const LENGTH: usize> SecureArray<T, LENGTH>
where
    T: Copy + Zeroize,
{
    pub fn new(mut content: [T; LENGTH]) -> Self {
        memlock::mlock(content.as_mut_ptr(), content.len());
        Self { content }
    }

    /// Borrow the contents of the string.
    pub fn unsecure(&self) -> &[T] {
        self.borrow()
    }

    /// Mutably borrow the contents of the string.
    pub fn unsecure_mut(&mut self) -> &mut [T] {
        self.borrow_mut()
    }

    /// Overwrite the string with zeros. This is automatically called in the destructor.
    pub fn zero_out(&mut self) {
        self.content.zeroize()
    }
}

impl<T: Copy + Zeroize, const LENGTH: usize> Clone for SecureArray<T, LENGTH> {
    fn clone(&self) -> Self {
        Self::new(self.content)
    }
}

// Creation
impl<T, const LENGTH: usize> From<[T; LENGTH]> for SecureArray<T, LENGTH>
where
    T: Copy + Zeroize,
{
    fn from(s: [T; LENGTH]) -> Self {
        Self::new(s)
    }
}

impl<T, const LENGTH: usize> TryFrom<Vec<T>> for SecureArray<T, LENGTH>
where
    T: Copy + Zeroize,
{
    type Error = String;

    fn try_from(s: Vec<T>) -> Result<Self, Self::Error> {
        Ok(Self::new(s.try_into().map_err(|error: Vec<T>| {
            format!("length mismatch: expected {LENGTH}, but got {}", error.len())
        })?))
    }
}

impl<const LENGTH: usize> FromStr for SecureArray<u8, LENGTH> {
    type Err = std::array::TryFromSliceError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(SecureArray::new(s.as_bytes().try_into()?))
    }
}

// Array item indexing
impl<T, U, const LENGTH: usize> std::ops::Index<U> for SecureArray<T, LENGTH>
where
    T: Copy + Zeroize,
    [T; LENGTH]: std::ops::Index<U>,
{
    type Output = <[T; LENGTH] as std::ops::Index<U>>::Output;

    fn index(&self, index: U) -> &Self::Output {
        std::ops::Index::index(&self.content, index)
    }
}

// Borrowing
impl<T, const LENGTH: usize> Borrow<[T]> for SecureArray<T, LENGTH>
where
    T: Copy + Zeroize,
{
    fn borrow(&self) -> &[T] {
        self.content.borrow()
    }
}

impl<T, const LENGTH: usize> BorrowMut<[T]> for SecureArray<T, LENGTH>
where
    T: Copy + Zeroize,
{
    fn borrow_mut(&mut self) -> &mut [T] {
        self.content.borrow_mut()
    }
}

// Overwrite memory with zeros when we're done
impl<T, const LENGTH: usize> Drop for SecureArray<T, LENGTH>
where
    T: Copy + Zeroize,
{
    fn drop(&mut self) {
        self.zero_out();
        memlock::munlock(self.content.as_mut_ptr(), self.content.len());
    }
}

// Make sure sensitive information is not logged accidentally
impl<T, const LENGTH: usize> fmt::Debug for SecureArray<T, LENGTH>
where
    T: Copy + Zeroize,
{
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str("***SECRET***").map_err(|_| fmt::Error)
    }
}

impl<T, const LENGTH: usize> fmt::Display for SecureArray<T, LENGTH>
where
    T: Copy + Zeroize,
{
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str("***SECRET***").map_err(|_| fmt::Error)
    }
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use super::SecureArray;

    #[test]
    fn test_basic() {
        let my_sec: SecureArray<_, 5> = SecureArray::from_str("hello").unwrap();
        assert_eq!(my_sec, SecureArray::from_str("hello").unwrap());
        assert_eq!(my_sec.unsecure(), b"hello");
    }

    #[test]
    #[cfg_attr(feature = "pre", pre::pre)]
    fn test_zero_out() {
        let mut my_sec: SecureArray<_, 5> = SecureArray::from_str("hello").unwrap();
        my_sec.zero_out();
        assert_eq!(my_sec.unsecure(), b"\x00\x00\x00\x00\x00");
    }

    #[test]
    fn test_comparison() {
        assert_eq!(SecureArray::<_, 5>::from_str("hello").unwrap(), SecureArray::from_str("hello").unwrap());
        assert_ne!(SecureArray::<_, 5>::from_str("hello").unwrap(), SecureArray::from_str("olleh").unwrap());
    }

    #[test]
    fn test_indexing() {
        let string: SecureArray<_, 5> = SecureArray::from_str("hello").unwrap();
        assert_eq!(string[0], b'h');
        assert_eq!(&string[3..5], "lo".as_bytes());
    }

    #[test]
    fn test_show() {
        assert_eq!(format!("{:?}", SecureArray::<_, 5>::from_str("hello").unwrap()), "***SECRET***".to_string());
        assert_eq!(format!("{}", SecureArray::<_, 5>::from_str("hello").unwrap()), "***SECRET***".to_string());
    }

    #[test]
    #[cfg_attr(feature = "pre", pre::pre)]
    fn test_comparison_zero_out_mb() {
        let mbstring1 = SecureArray::from(['H', 'a', 'l', 'l', 'o', ' ', '🦄', '!']);
        let mbstring2 = SecureArray::from(['H', 'a', 'l', 'l', 'o', ' ', '🦄', '!']);
        let mbstring3 = SecureArray::from(['!', '🦄', ' ', 'o', 'l', 'l', 'a', 'H']);
        assert!(mbstring1 == mbstring2);
        assert!(mbstring1 != mbstring3);

        let mut mbstring = mbstring1.clone();
        mbstring.zero_out();
        assert_eq!(mbstring.unsecure(), &['\0', '\0', '\0', '\0', '\0', '\0', '\0', '\0']);
    }
}
