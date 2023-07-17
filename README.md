[![crates.io](https://img.shields.io/crates/v/secstr?logo=rust) ![](https://img.shields.io/crates/d/secstr)](https://crates.io/crates/secstr)
[![API Docs](https://docs.rs/secstr/badge.svg)](https://docs.rs/secstr/)
[![CI status](https://ci.codeberg.org/api/badges/valpackett/secstr/status.svg)](https://ci.codeberg.org/valpackett/secstr)
[![unlicense](https://img.shields.io/badge/un-license-green.svg?style=flat)](https://unlicense.org)
[![Support me on Patreon](https://img.shields.io/badge/dynamic/json?logo=patreon&color=%23e85b46&label=support%20me%20on%20patreon&query=data.attributes.patron_count&suffix=%20patrons&url=https%3A%2F%2Fwww.patreon.com%2Fapi%2Fcampaigns%2F9395291)](https://www.patreon.com/valpackett)

# secstr

A [Rust] library that implements a data type (wrapper around `Vec<u8>` and other types) suitable for storing sensitive information such as passwords and private keys in memory.
Inspired by Haskell [securemem] and .NET [SecureString].

Featuring:

- constant time comparison (does not short circuit on the first different character; but terminates instantly if strings have different length)
- automatically zeroing out in the destructor using [zeroize]
- `mlock` and `madvise` protection if possible
- formatting as `***SECRET***` to prevent leaking into logs
- (optionally) using libsodium (through [sodiumoxide]'s [libsodium-sys]) for comparison, and hashing (`std::hash::Hash`)
- (optionally) de/serializable into anything [Serde] supports as a byte string
- (optionally) compile-time checked [preconditions] for the public `unsafe` API

[Rust]: https://www.rust-lang.org
[securemem]: https://hackage.haskell.org/package/securemem
[SecureString]: http://msdn.microsoft.com/en-us/library/system.security.securestring%28v=vs.110%29.aspx
[zeroize]: https://crates.io/crates/zeroize
[sodiumoxide]: https://crates.io/crates/sodiumoxide
[libsodium-sys]: https://crates.io/crates/libsodium-sys
[Serde]: https://serde.rs/
[preconditions]: https://crates.io/crates/pre

## Usage

```rust
use secstr::*;

let pw = SecStr::from("correct horse battery staple");

// Compared in constant time:
// (Obviously, you should store hashes in real apps, not plaintext passwords)
let are_pws_equal = pw == SecStr::from("correct horse battery staple".to_string()); // true

// Formatting, printing without leaking secrets into logs
let text_to_print = format!("{}", SecStr::from("hello")); // "***SECRET***"

// Clearing memory
// THIS IS DONE AUTOMATICALLY IN THE DESTRUCTOR
// (but you can force it)
let mut my_sec = SecStr::from("hello");
my_sec.zero_out();
// (It also sets the length to 0)
assert_eq!(my_sec.unsecure(), b"");
```

Be careful with `SecStr::from`: if you have a borrowed string, it will be copied.  
Use `SecStr::new` if you have a `Vec<u8>`.

## License

This is free and unencumbered software released into the public domain.  
For more information, please refer to the `UNLICENSE` file or [unlicense.org](https://unlicense.org).
