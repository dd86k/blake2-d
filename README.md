# blake2-d

BLAKE2 library written in D implementing the BLAKE2b and BLAKE2s hashing
algorithms and is compatible with the Phobos Digest API (std.digest).

BLAKE2 was introduced in 2015 as IETF RFC 7693. You can visit
[the website](https://www.blake2.net/) for more information.

Features (still WIP!):

- [x] BLAKE2b-512 and BLAKE2s-256.
- [x] Custom digest sizes.
- [x] Supports keying dynamically.
- [ ] Supports keying at compile-time.
- [ ] BLAKE2bp and BLAKE2sp variants.

NOTE: May be incompatible with HMAC.

Compatible and tested with DMD, GDC, and LDC.

Pull Requests accepted.

**If you would like to disclose a vulnerability, please consult [SECURITY.md](../master/.github/SECURITY.md).**

# Usage

To include it in your project, simply import the `blake2d` package.

## Digest API

If you are unfamiliar with the Digest API, here is a quick summary.

Two APIs are available: Template API and OOP API.

### Template API

The template API uses a structure template and is a good choice if your
application only plans to support one digest algorithm.

```d
// NOTE: hexString is from std.conv
BLAKE2b512 b2b512;
b2b512.put("abc");
assert(b2b512.finish() == cast(ubyte[]) hexString!(
    "ba80a53f981c4d0d6a2797b69f12f6e94c212f14685ac4b74b12bb6fdbffa2d1"~
    "7d87c5392aab792dc252d5de4533cc9518d38aa8dbf1925ab92386edd4009923"));
b2b512.start(); // reset
b2b512.put("abcdef");
assert(b2b512.finish() == cast(ubyte[]) hexString!(
    "dde410524e3569b303e494aa82a3afb3e426f9df24c1398e9ff87aafbc2f5b7b"~
    "3c1a4c9400409de3b45d37a00e5eae2a93cc9c4a108b00f05217d41a424d2b8a"));
```

### OOP API

The OOP API uses a class (object) implementation and is a good choice if
your application plans to support one or more digest algorithms.

```d
import std.string : representation;
import std.conv : hexString;

Digest dgst = new BLAKE2b512Digest();
dgst.put("abc");
assert(dgst.finish() == cast(ubyte[]) hexString!(
    "ba80a53f981c4d0d6a2797b69f12f6e94c212f14685ac4b74b12bb6fdbffa2d1"~
    "7d87c5392aab792dc252d5de4533cc9518d38aa8dbf1925ab92386edd4009923"));
dgst.reset();
dgst.put("abcdef");
assert(dgst.finish() == cast(ubyte[]) hexString!(
    "dde410524e3569b303e494aa82a3afb3e426f9df24c1398e9ff87aafbc2f5b7b"~
    "3c1a4c9400409de3b45d37a00e5eae2a93cc9c4a108b00f05217d41a424d2b8a"));
```

There are numerous ways to avoid GC allocation. For example when only using a
digest for a one-time use in a short scope, there's `std.typecons.scoped`.

### Keying

Currently, the only way to supply a key is with the `key` function:

```d
import std.string : representation;
import std.conv : hexString;

// Key can be between 1 to 32 bytes for BLAKE2s256
// and 1 to 64 bytes for BLAKE2b512.
auto secret = hexString!(
    "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
    .representation;
// Vector from official suite.
auto data = hexString!("000102").representation;

BLAKE2s256 b2s;
b2s.key(secret);
b2s.put(data);

assert(b2s.finish().toHexString!(LetterCase.lower) ==
    "1d220dbe2ee134661fdf6d9e74b41704710556f2f6e5a091b227697445dbea6b");
```

# License

Published under the Boost License 1.0.