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
///
/// Be careful with `SecureBytes::from`: if you have a borrowed string, it will be copied.
/// Use `SecureBytes::new` if you have a `Vec<u8>`.
#[derive(PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SecureVec<T>
where
    T: Copy + Zeroize,
{
    pub(crate) content: Vec<T>,
}

/// Type alias for a vector that stores just bytes
pub type SecureBytes = SecureVec<u8>;

impl<T> SecureVec<T>
where
    T: Copy + Zeroize,
{
    pub fn new(mut cont: Vec<T>) -> Self {
        memlock::mlock(cont.as_mut_ptr(), cont.capacity());
        SecureVec { content: cont }
    }

    /// Borrow the contents of the string.
    pub fn unsecure(&self) -> &[T] {
        self.borrow()
    }

    /// Mutably borrow the contents of the string.
    pub fn unsecure_mut(&mut self) -> &mut [T] {
        self.borrow_mut()
    }

    /// Resizes the `SecureVec` in-place so that len is equal to `new_len`.
    ///
    /// If `new_len` is smaller the inner vector is truncated.
    /// If `new_len` is larger the inner vector will grow, placing `value` in all new cells.
    ///
    /// This ensures that the new memory region is secured if reallocation occurs.
    ///
    /// Similar to [`Vec::resize`](https://doc.rust-lang.org/std/vec/struct.Vec.html#method.resize)
    pub fn resize(&mut self, new_len: usize, value: T) {
        // Trucnate if shorter or same length
        if new_len <= self.content.len() {
            self.content.truncate(new_len);
            return;
        }

        // Allocate new vector, copy old data into it
        let mut new_vec = vec![value; new_len];
        memlock::mlock(new_vec.as_mut_ptr(), new_vec.capacity());
        new_vec[0..self.content.len()].copy_from_slice(&self.content);

        // Securely clear old vector, replace with new vector
        self.zero_out();
        memlock::munlock(self.content.as_mut_ptr(), self.content.capacity());
        self.content = new_vec;
    }

    /// Overwrite the string with zeros. This is automatically called in the destructor.
    ///
    /// This also sets the length to `0`.
    pub fn zero_out(&mut self) {
        self.content.zeroize()
    }
}

impl<T: Copy + Zeroize> Clone for SecureVec<T> {
    fn clone(&self) -> Self {
        Self::new(self.content.clone())
    }
}

// Creation
impl<T, U> From<U> for SecureVec<T>
where
    U: Into<Vec<T>>,
    T: Copy + Zeroize,
{
    fn from(s: U) -> SecureVec<T> {
        SecureVec::new(s.into())
    }
}

impl FromStr for SecureVec<u8> {
    type Err = std::convert::Infallible;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(SecureVec::new(s.into()))
    }
}

// Vec item indexing
impl<T, U> std::ops::Index<U> for SecureVec<T>
where
    T: Copy + Zeroize,
    Vec<T>: std::ops::Index<U>,
{
    type Output = <Vec<T> as std::ops::Index<U>>::Output;

    fn index(&self, index: U) -> &Self::Output {
        std::ops::Index::index(&self.content, index)
    }
}

// Borrowing
impl<T> Borrow<[T]> for SecureVec<T>
where
    T: Copy + Zeroize,
{
    fn borrow(&self) -> &[T] {
        self.content.borrow()
    }
}

impl<T> BorrowMut<[T]> for SecureVec<T>
where
    T: Copy + Zeroize,
{
    fn borrow_mut(&mut self) -> &mut [T] {
        self.content.borrow_mut()
    }
}

// Overwrite memory with zeros when we're done
impl<T> Drop for SecureVec<T>
where
    T: Copy + Zeroize,
{
    fn drop(&mut self) {
        self.zero_out();
        memlock::munlock(self.content.as_mut_ptr(), self.content.capacity());
    }
}

// Make sure sensitive information is not logged accidentally
impl<T> fmt::Debug for SecureVec<T>
where
    T: Copy + Zeroize,
{
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str("***SECRET***").map_err(|_| fmt::Error)
    }
}

impl<T> fmt::Display for SecureVec<T>
where
    T: Copy + Zeroize,
{
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str("***SECRET***").map_err(|_| fmt::Error)
    }
}

#[cfg(test)]
mod tests {
    use super::{SecureBytes, SecureVec};

    #[test]
    fn test_basic() {
        let my_sec = SecureBytes::from("hello");
        assert_eq!(my_sec, SecureBytes::from("hello".to_string()));
        assert_eq!(my_sec.unsecure(), b"hello");
    }

    #[test]
    #[cfg_attr(feature = "pre", pre::pre)]
    fn test_zero_out() {
        let mut my_sec = SecureBytes::from("hello");
        my_sec.zero_out();
        // `zero_out` sets the `len` to 0, here we reset it to check that the bytes were zeroed
        #[cfg_attr(
            feature = "pre",
            forward(impl pre::std::vec::Vec),
            assure(
                new_len <= self.capacity(),
                reason = "the call to `zero_out` did not reduce the capacity and the length was `5` before,
                so the capacity must be greater or equal to `5`"
            ),
            assure(
                "the elements at `old_len..new_len` are initialized",
                reason = "they were initialized to `0` by the call to `zero_out`"
            )
        )]
        unsafe {
            my_sec.content.set_len(5)
        }
        assert_eq!(my_sec.unsecure(), b"\x00\x00\x00\x00\x00");
    }

    #[test]
    fn test_resize() {
        let mut my_sec = SecureVec::from([0, 1]);
        assert_eq!(my_sec.unsecure().len(), 2);
        my_sec.resize(1, 0);
        assert_eq!(my_sec.unsecure().len(), 1);
        my_sec.resize(16, 2);
        assert_eq!(my_sec.unsecure(), &[0, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2]);
    }

    #[test]
    fn test_comparison() {
        assert_eq!(SecureBytes::from("hello"), SecureBytes::from("hello"));
        assert!(SecureBytes::from("hello") != SecureBytes::from("yolo"));
        assert!(SecureBytes::from("hello") != SecureBytes::from("olleh"));
        assert!(SecureBytes::from("hello") != SecureBytes::from("helloworld"));
        assert!(SecureBytes::from("hello") != SecureBytes::from(""));
    }

    #[test]
    fn test_indexing() {
        let string = SecureBytes::from("hello");
        assert_eq!(string[0], b'h');
        assert_eq!(&string[3..5], "lo".as_bytes());
    }

    #[test]
    fn test_show() {
        assert_eq!(format!("{:?}", SecureBytes::from("hello")), "***SECRET***".to_string());
        assert_eq!(format!("{}", SecureBytes::from("hello")), "***SECRET***".to_string());
    }

    #[test]
    #[cfg_attr(feature = "pre", pre::pre)]
    fn test_comparison_zero_out_mb() {
        let mbstring1 = SecureVec::from(vec!['H', 'a', 'l', 'l', 'o', ' ', '🦄', '!']);
        let mbstring2 = SecureVec::from(vec!['H', 'a', 'l', 'l', 'o', ' ', '🦄', '!']);
        let mbstring3 = SecureVec::from(vec!['!', '🦄', ' ', 'o', 'l', 'l', 'a', 'H']);
        assert!(mbstring1 == mbstring2);
        assert!(mbstring1 != mbstring3);

        let mut mbstring = mbstring1.clone();
        mbstring.zero_out();
        // `zero_out` sets the `len` to 0, here we reset it to check that the bytes were zeroed
        #[cfg_attr(
            feature = "pre",
            forward(impl pre::std::vec::Vec),
            assure(
                new_len <= self.capacity(),
                reason = "the call to `zero_out` did not reduce the capacity and the length was `8` before,
                so the capacity must be greater or equal to `8`"
            ),
            assure(
                "the elements at `old_len..new_len` are initialized",
                reason = "they were initialized to `0` by the call to `zero_out`"
            )
        )]
        unsafe {
            mbstring.content.set_len(8)
        }
        assert_eq!(mbstring.unsecure(), &['\0', '\0', '\0', '\0', '\0', '\0', '\0', '\0']);
    }
}
