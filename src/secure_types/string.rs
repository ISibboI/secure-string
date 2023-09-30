use core::fmt;
use std::str::FromStr;

use crate::{secure_utils::memlock, SecureVec};

/// Wrapper for a vector that stores a valid UTF-8 string
#[derive(Clone, Eq)]
pub struct SecureString(SecureVec<u8>);

impl SecureString {
    /// Borrow the contents of the string.
    #[cfg_attr(feature = "pre", pre::pre)]
    pub fn unsecure(&self) -> &str {
        #[cfg_attr(
            feature = "pre",
            forward(pre),
            assure(
                "the content of `v` is valid UTF-8",
                reason = "it is not possible to create a `SecureString` with invalid UTF-8 content
                and it is also not possible to modify the content as non-UTF-8 directly, so
                they must still be valid UTF-8 here"
            )
        )]
        unsafe {
            std::str::from_utf8_unchecked(self.0.unsecure())
        }
    }

    /// Mutably borrow the contents of the string.
    #[cfg_attr(feature = "pre", pre::pre)]
    pub fn unsecure_mut(&mut self) -> &mut str {
        #[cfg_attr(
            feature = "pre",
            forward(pre),
            assure(
                "the content of `v` is valid UTF-8",
                reason = "it is not possible to create a `SecureString` with invalid UTF-8 content
                and it is also not possible to modify the content as non-UTF-8 directly, so
                they must still be valid UTF-8 here"
            )
        )]
        unsafe {
            std::str::from_utf8_unchecked_mut(self.0.unsecure_mut())
        }
    }

    /// Turn the string into a regular `String` again.
    #[cfg_attr(feature = "pre", pre::pre)]
    pub fn into_unsecure(mut self) -> String {
        memlock::munlock(self.0.content.as_mut_ptr(), self.0.content.capacity());
        let content = std::mem::take(&mut self.0.content);
        std::mem::forget(self);
        #[cfg_attr(
            feature = "pre",
            forward(impl pre::std::string::String),
            assure(
                "the content of `bytes` is valid UTF-8",
                reason = "it is not possible to create a `SecureString` with invalid UTF-8 content
                and it is also not possible to modify the content as non-UTF-8 directly, so
                they must still be valid UTF-8 here"
            )
        )]
        unsafe {
            String::from_utf8_unchecked(content)
        }
    }
}

impl PartialEq for SecureString {
    fn eq(&self, other: &SecureString) -> bool {
        // use implementation of SecureVec
        self.0 == other.0
    }
}

impl fmt::Debug for SecureString {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str("***SECRET***").map_err(|_| fmt::Error)
    }
}

impl fmt::Display for SecureString {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str("***SECRET***").map_err(|_| fmt::Error)
    }
}

impl<U> From<U> for SecureString
where
    U: Into<String>,
{
    fn from(s: U) -> SecureString {
        SecureString(SecureVec::new(s.into().into_bytes()))
    }
}

impl FromStr for SecureString {
    type Err = std::convert::Infallible;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(SecureString(SecureVec::new(s.into())))
    }
}

#[cfg(feature = "serde")]
impl serde::Serialize for SecureString {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(self.unsecure())
    }
}

#[cfg(feature = "serde")]
impl<'de> serde::Deserialize<'de> for SecureString {
    fn deserialize<D>(deserializer: D) -> Result<SecureString, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        struct SecureStringVisitor;
        impl<'de> serde::de::Visitor<'de> for SecureStringVisitor {
            type Value = SecureString;
            fn expecting(&self, formatter: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
                write!(formatter, "an utf-8 encoded string")
            }
            fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                Ok(SecureString::from(v.to_string()))
            }
        }
        deserializer.deserialize_string(SecureStringVisitor)
    }
}
