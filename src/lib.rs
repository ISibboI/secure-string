//! A data type suitable for storing sensitive information such as passwords and private keys in memory, featuring constant time equality, mlock and zeroing out.

mod secure_types;
mod secure_utils;

#[cfg(feature = "serde")]
mod serde;

pub use secure_types::{array::SecureArray, boxed::SecureBox, string::SecureString, vec::SecureBytes, vec::SecureVec};

#[doc = include_str!("../README.md")]
#[cfg(doctest)]
pub struct ReadmeDoctests;
