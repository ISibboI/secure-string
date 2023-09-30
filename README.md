# Secure String

[![crates.io](https://img.shields.io/crates/v/secure-string?logo=rust)![crates.io](https://img.shields.io/crates/d/secure-string)](https://crates.io/crates/secure-string)
[![API Docs](https://docs.rs/secure-string/badge.svg)](https://docs.rs/secure-string/)
[![unlicense](https://img.shields.io/badge/un-license-green.svg?style=flat)](https://unlicense.org)

A [Rust] library that implements a data type (wrapper around `Vec<u8>` and other types) suitable for storing sensitive information such as passwords and private keys in memory.
Inspired by Haskell [securemem] and .NET [SecureString].

Featuring:

- Various secure datatypes: `SecureVec`, `SecureBytes`, `SecureArray`, `SecureString`, `SecureBox`
- timing-attack-resistant comparison (does not short circuit on the first different character; but terminates instantly if strings have different length)
- automatically zeroing out in the destructor using [zeroize]
- `mlock` and `madvise` protection if possible
- formatting as `***SECRET***` to prevent leaking into logs
- (optionally) de/serializable into anything [Serde] supports as a byte string
- (optionally) compile-time checked [preconditions] for the public `unsafe` API

[Rust]: https://www.rust-lang.org
[securemem]: https://hackage.haskell.org/package/securemem
[SecureString]: http://msdn.microsoft.com/en-us/library/system.security.securestring%28v=vs.110%29.aspx
[zeroize]: https://crates.io/crates/zeroize
[Serde]: https://serde.rs/
[preconditions]: https://crates.io/crates/pre

## Usage

```rust
use secure_string::*;

let pw = SecureString::from("correct horse battery staple");

// Compared in constant time:
// (Obviously, you should store hashes in real apps, not plaintext passwords)
let are_pws_equal = pw == SecureString::from("correct horse battery staple".to_string()); // true

// Formatting, printing without leaking secrets into logs
let text_to_print = format!("{}", SecureString::from("hello")); // "***SECRET***"

// Clearing memory
// THIS IS DONE AUTOMATICALLY IN THE DESTRUCTOR
// (but you can force it)
let mut my_sec = SecureString::from("hello");
my_sec.zero_out();
// (It also sets the length to 0)
assert_eq!(my_sec.unsecure(), b"");
```

Be careful with `SecureString::from`: if you have a borrowed string, it will be copied.  
Use `SecureString::new` if you have a `Vec<u8>`.

## License

This is free and unencumbered software released into the public domain.  
For more information, please refer to the `UNLICENSE` file or [unlicense.org](https://unlicense.org).
