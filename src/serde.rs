use core::fmt;
use std::borrow::Borrow;

use serde::{
    de::{self, Visitor},
    Deserialize, Deserializer, Serialize, Serializer,
};

use crate::{SecureBytes, SecureVec};

struct BytesVisitor;

impl<'de> Visitor<'de> for BytesVisitor {
    type Value = SecureVec<u8>;

    fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        formatter.write_str("a byte array or a sequence of bytes")
    }

    fn visit_bytes<E>(self, value: &[u8]) -> Result<SecureVec<u8>, E>
    where
        E: de::Error,
    {
        Ok(SecureBytes::from(value))
    }

    fn visit_byte_buf<E>(self, value: Vec<u8>) -> Result<SecureVec<u8>, E>
    where
        E: de::Error,
    {
        Ok(SecureBytes::from(value))
    }

    fn visit_seq<A>(self, mut seq: A) -> Result<SecureVec<u8>, A::Error>
    where
        A: de::SeqAccess<'de>,
    {
        let mut value: Vec<u8> = Vec::with_capacity(seq.size_hint().unwrap_or(0));

        while let Some(element) = seq.next_element()? {
            value.push(element);
        }

        Ok(SecureBytes::from(value))
    }
}

impl<'de> Deserialize<'de> for SecureVec<u8> {
    fn deserialize<D>(deserializer: D) -> Result<SecureVec<u8>, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_bytes(BytesVisitor)
    }
}

impl Serialize for SecureVec<u8> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_bytes(self.content.borrow())
    }
}

#[cfg(test)]
mod tests {
    use crate::{SecureBytes, SecureVec};

    #[cfg(feature = "serde")]
    #[test]
    fn test_serialization() {
        use serde_cbor::{from_slice, to_vec};
        let my_sec = SecureBytes::from("hello");
        let my_cbor = to_vec(&my_sec).unwrap();
        assert_eq!(my_cbor, b"\x45hello");
        let my_sec2 = from_slice(&my_cbor).unwrap();
        assert_eq!(my_sec, my_sec2);
    }

    #[cfg(feature = "serde")]
    #[test]
    fn test_serde_json() {
        let secure_bytes = SecureVec::from("abc".as_bytes());

        let json = serde_json::to_string_pretty(secure_bytes.unsecure()).unwrap();
        println!("json = {json}");

        let secure_bytes_serde: SecureVec<u8> = serde_json::from_str(&json).unwrap();

        assert_eq!(secure_bytes, secure_bytes_serde);
    }
}
