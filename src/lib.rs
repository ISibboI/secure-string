//! A data type suitable for storing sensitive information such as passwords and private keys in memory, featuring constant time equality, mlock and zeroing out.

mod secure_types;
mod secure_utils;

#[cfg(feature = "serde")]
mod serde;

pub use secure_types::{array::SecureArray, boxed::SecureBox, string::SecureString, vec::SecureBytes, vec::SecureVec};

mod private {
    // Private trait to prevent users from implementing `NoPaddingBytes`
    // This allows to change to a better implementation of `NoPaddingBytes` in the future,
    // without worrying about breaking backwards compatibility for users who implemented the trait.
    pub trait Sealed {}
}
/// Guarantees that there are no padding bytes in types implementing this trait.
///
/// This trait is sealed and cannot be implemented outside of this crate.
///
/// # Safety
///
/// Only implement for types without padding bytes.
pub unsafe trait NoPaddingBytes: private::Sealed {}

macro_rules! impl_no_padding_bytes {
    ($($type:ty),*) => {
        $(
            impl private::Sealed for $type {}
            unsafe impl NoPaddingBytes for $type {}
        )*
    };
}

impl_no_padding_bytes! {
    u8, i8, u16, i16, u32, i32, u64, i64, u128, i128, usize, isize,
    char, f32, f64, ()
}

impl<T: NoPaddingBytes, const N: usize> private::Sealed for [T; N] {}
unsafe impl<T: NoPaddingBytes, const N: usize> NoPaddingBytes for [T; N] {}
