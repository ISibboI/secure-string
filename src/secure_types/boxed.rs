use core::fmt;
use std::{
    borrow::{Borrow, BorrowMut},
    mem::MaybeUninit,
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
pub struct SecureBox<T>
where
    T: Copy,
{
    // This is an `Option` to avoid UB in the destructor, outside the destructor, it is always
    // `Some(_)`
    content: Option<Box<T>>,
}

impl<T> SecureBox<T>
where
    T: Copy,
{
    pub fn new(mut cont: Box<T>) -> Self {
        memlock::mlock(&mut cont, 1);
        SecureBox { content: Some(cont) }
    }

    /// Borrow the contents of the string.
    pub fn unsecure(&self) -> &T {
        self.content.as_ref().unwrap()
    }

    /// Mutably borrow the contents of the string.
    pub fn unsecure_mut(&mut self) -> &mut T {
        self.content.as_mut().unwrap()
    }
}

impl<T: Copy> Clone for SecureBox<T> {
    fn clone(&self) -> Self {
        Self::new(self.content.clone().unwrap())
    }
}

// Delegate indexing
impl<T, U> std::ops::Index<U> for SecureBox<T>
where
    T: std::ops::Index<U> + Copy,
{
    type Output = <T as std::ops::Index<U>>::Output;

    fn index(&self, index: U) -> &Self::Output {
        std::ops::Index::index(self.content.as_ref().unwrap().as_ref(), index)
    }
}

// Borrowing
impl<T> Borrow<T> for SecureBox<T>
where
    T: Copy,
{
    fn borrow(&self) -> &T {
        self.content.as_ref().unwrap()
    }
}
impl<T> BorrowMut<T> for SecureBox<T>
where
    T: Copy,
{
    fn borrow_mut(&mut self) -> &mut T {
        self.content.as_mut().unwrap()
    }
}

// Overwrite memory with zeros when we're done
impl<T> Drop for SecureBox<T>
where
    T: Copy,
{
    #[cfg_attr(feature = "pre", pre::pre)]
    fn drop(&mut self) {
        // Make sure that the box does not need to be dropped after this function, because it may
        // see an invalid type, if `T` does not support an all-zero byte-pattern
        // Instead we manually destruct the box and only handle the potentially invalid values
        // behind the pointer
        let ptr = Box::into_raw(self.content.take().unwrap());

        // There is no need to worry about dropping the contents, because `T: Copy` and `Copy`
        // types cannot implement `Drop`

        unsafe {
            std::slice::from_raw_parts_mut::<MaybeUninit<u8>>(ptr as *mut MaybeUninit<u8>, std::mem::size_of::<T>()).zeroize();
        }

        memlock::munlock(ptr, 1);

        // Deallocate only non-zero-sized types, because otherwise it's UB
        if std::mem::size_of::<T>() != 0 {
            // Safety:
            // This way to manually deallocate is advertised in the documentation of `Box::into_raw`.
            // The box was allocated with the global allocator and a layout of `T` and is thus
            // deallocated using the same allocator and layout here.
            unsafe { std::alloc::dealloc(ptr as *mut u8, std::alloc::Layout::new::<T>()) };
        }
    }
}

// Make sure sensitive information is not logged accidentally
impl<T> fmt::Debug for SecureBox<T>
where
    T: Copy,
{
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str("***SECRET***").map_err(|_| fmt::Error)
    }
}

impl<T> fmt::Display for SecureBox<T>
where
    T: Copy,
{
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str("***SECRET***").map_err(|_| fmt::Error)
    }
}

#[cfg(test)]
mod tests {
    use std::mem::MaybeUninit;

    use zeroize::Zeroize;

    use super::SecureBox;

    const PRIVATE_KEY_1: [u8; 32] = [
        0xb0, 0x3b, 0x34, 0xc3, 0x3a, 0x1c, 0x44, 0xf2, 0x25, 0xb6, 0x62, 0xd2, 0xbf, 0x48, 0x59, 0xb8, 0x13, 0x54, 0x11, 0xfa,
        0x7b, 0x03, 0x86, 0xd4, 0x5f, 0xb7, 0x5d, 0xc5, 0xb9, 0x1b, 0x44, 0x66,
    ];

    const PRIVATE_KEY_2: [u8; 32] = [
        0xc8, 0x06, 0x43, 0x9d, 0xc9, 0xd2, 0xc4, 0x76, 0xff, 0xed, 0x8f, 0x25, 0x80, 0xc0, 0x88, 0x8d, 0x58, 0xab, 0x40, 0x6b,
        0xf7, 0xae, 0x36, 0x98, 0x87, 0x90, 0x21, 0xb9, 0x6b, 0xb4, 0xbf, 0x59,
    ];

    /// Overwrite the contents with zeros. This is automatically done in the destructor.
    ///
    /// # Safety
    /// An all-zero byte-pattern must be a valid value of `T` in order for this function call to not be
    /// undefined behavior.
    #[cfg_attr(feature = "pre", pre::pre("an all-zero byte-pattern is a valid value of `T`"))]
    pub(crate) unsafe fn zero_out_secure_box<T>(secure_box: &mut SecureBox<T>)
    where
        T: Copy,
    {
        std::slice::from_raw_parts_mut::<MaybeUninit<u8>>(
            &mut **secure_box.content.as_mut().unwrap() as *mut T as *mut MaybeUninit<u8>,
            std::mem::size_of::<T>(),
        )
        .zeroize();
    }

    #[test]
    #[cfg_attr(feature = "pre", pre::pre)]
    fn test_secure_box() {
        let key_1 = SecureBox::new(Box::new(PRIVATE_KEY_1));
        let key_2 = SecureBox::new(Box::new(PRIVATE_KEY_2));
        let key_3 = SecureBox::new(Box::new(PRIVATE_KEY_1));
        assert!(key_1 == key_1);
        assert!(key_1 != key_2);
        assert!(key_2 != key_3);
        assert!(key_1 == key_3);

        let mut final_key = key_1.clone();
        #[cfg_attr(
            feature = "pre",
            assure(
                "an all-zero byte-pattern is a valid value of `T`",
                reason = "`T` is `i32`, for which an all-zero byte-pattern is valid"
            )
        )]
        unsafe {
            zero_out_secure_box(&mut final_key)
        };
        assert_eq!(final_key.unsecure(), &[0; 32]);
    }
}
