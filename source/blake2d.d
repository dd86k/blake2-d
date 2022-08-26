/// Computes BLAKE2 hashes of arbitrary data using a native implementation.
/// Standards: IETF RFC 7693
/// License: $(LINK2 https://www.boost.org/LICENSE_1_0.txt, Boost License 1.0)
/// Authors: $(LINK2 https://github.com/dd86k, dd86k)
module blake2d;

// NOTE: The Phobos Digest API have no support for keyed hashes.

/// Version string of blake2-d that can be used for printing purposes.
public enum BLAKE2D_VERSION_STRING = "0.3.0";

private import std.digest;
private import core.bitop : ror;

// "For BLAKE2b, the two extra permutations for rounds 10 and 11 are
// SIGMA[10..11] = SIGMA[0..1]."
/// Sigma scheduling.
private immutable ubyte[16][12] SIGMA = [
    [ 0,  1,  2,  3,  4,  5,  6,  7,  8,  9,  10, 11, 12, 13, 14, 15, ],
    [ 14, 10, 4,  8,  9,  15, 13, 6,  1,  12, 0,  2,  11, 7,  5,  3,  ],
    [ 11, 8,  12, 0,  5,  2,  15, 13, 10, 14, 3,  6,  7,  1,  9,  4,  ],
    [ 7,  9,  3,  1,  13, 12, 11, 14, 2,  6,  5,  10, 4,  0,  15, 8,  ],
    [ 9,  0,  5,  7,  2,  4,  10, 15, 14, 1,  11, 12, 6,  8,  3,  13, ],
    [ 2,  12, 6,  10, 0,  11, 8,  3,  4,  13, 7,  5,  15, 14, 1,  9,  ],
    [ 12, 5,  1,  15, 14, 13, 4,  10, 0,  7,  6,  3,  9,  2,  8,  11, ],
    [ 13, 11, 7,  14, 12, 1,  3,  9,  5,  0,  15, 4,  8,  6,  2,  10, ],
    [ 6,  15, 14, 9,  11, 3,  0,  8,  12, 2,  13, 7,  1,  4,  10, 5,  ],
    [ 10, 2,  8,  4,  7,  6,  1,  5,  15, 11, 9,  14, 3,  12, 13, 0,  ],
    [ 0,  1,  2,  3,  4,  5,  6,  7,  8,  9,  10, 11, 12, 13, 14, 15, ],
    [ 14, 10, 4,  8,  9,  15, 13, 6,  1,  12, 0,  2,  11, 7,  5,  3,  ],
];

/// BLAKE2b IVs
private immutable ulong[8] B2B_IV = [
    0x6a09e667f3bcc908, 0xbb67ae8584caa73b,
    0x3c6ef372fe94f82b, 0xa54ff53a5f1d36f1,
    0x510e527fade682d1, 0x9b05688c2b3e6c1f,
    0x1f83d9abfb41bd6b, 0x5be0cd19137e2179
];

/// BLAKE2s IVs
private immutable uint[8] B2S_IV = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
    0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
];

//TODO: To remove by 0.4.0 or later.
/// Used with the BLAKE2 structure template to make the BLAKE2s and BLAKE2b
/// aliases.
deprecated("Use BLAKE2b, BLAKE2s, or BLAKE2Impl structure templates. This will be removed in 0.4.0")
enum BLAKE2Variant {
    b,  /// BLAKE2b
    s,  /// BLAKE2s
}

/// Template API alias for BLAKE2b-512.
public alias BLAKE2b512 = BLAKE2b!();
/// Alias to BLAKE2b512.
/// 
/// This is the recommended alias to use for most cases.
public alias BLAKE2 = BLAKE2b512;
/// Template API alias for BLAKE2s-256.
public alias BLAKE2s256 = BLAKE2s!();

/// BLAKE2b structure template.
///
/// Use this if you wish to set a custom digest size and a key (compile-time).
/// It is recommended to use the BLAKE2b512 alias over this.
///
/// Params:
///     digestSize = Output digest size in bits. Optional.
///     key = User-supplied key, cannot exceed 64 bytes. Optional.
struct BLAKE2b(uint digestSize = 512)
{
    static assert(digestSize >= 8 && digestSize <= 512,
        "BLAKE2b digest size must be between 8 and 512 bits.");
    BLAKE2Impl!(ulong, digestSize, B2B_IV, 12, 32, 24, 16, 63) instance;
    alias instance this;
}

/// BLAKE2s structure template.
///
/// Use this if you wish to set a custom digest size and a key (compile-time).
/// It is recommended to use the BLAKE2s256 alias over this.
///
/// Params:
///     digestSize = Output digest size in bits. Optional.
///     key = User-supplied key, cannot exceed 32 bytes. Optional.
struct BLAKE2s(uint digestSize = 256)
{
    static assert(digestSize >= 8 && digestSize <= 256,
        "BLAKE2s digest size must be between 8 and 256 bits.");
    BLAKE2Impl!(uint, digestSize, B2S_IV, 10, 16, 12, 8, 7) instance;
    alias instance this;
}

/// BLAKE2 implementation.
///
/// It is strongly recommended to use the BLAKE2b512 and BLAKE2s256 aliases
/// instead of playing with this.
/// 
/// If you wish to set a digest size, use the BLAKE2b and BLAKE2s structure
/// templates.
///
/// BLAKE2X (XOF) is not supported.
///
/// Examples:
/// ---
/// // Defines BLAKE2s160 with Template API, OOP API, and helper function.
/// alias BLAKE2s160 = BLAKE2s!(160);
/// auto blake2s160_Of(T...)(T data) { return digest!(BLAKE2s160, T)(data); }
/// public alias BLAKE2s160Digest = WrapperDigest!BLAKE2s160;
/// ---
///
/// Params:
///     T = Type alias. ulong for BLAKE2b and uint for BLAKE2s. Untested with other types.
///     digestSize = Digest size in bits.
///     iv = Initial vectors. If userkey is supplied, this is ignored.
///     userkey = Compile-time key.
///     ROUNDS = Number of rounds when compressing.
///     R1 = R1 value for G function.
///     R2 = R2 value for G function.
///     R3 = R3 value for G function.
///     R4 = R4 value for G function. 
///
/// Throws: No exceptions are thrown.
struct BLAKE2Impl(T, uint digestSize, alias iv,
    size_t ROUNDS, uint R1, uint R2, uint R3, uint R4)
{
    @safe: @nogc: nothrow: pure:
    
    static assert(digestSize > 0, "Digest size must higher than zero.");
    static assert(digestSize % 8 == 0, "Digest size must be divisible by 8.");
    
    enum blockSize = digestSize;    /// Digest size in bits.
    
    /// Initiate or reset the state of the instance.
    void start()
    {
        this = typeof(this).init;
    }
    
    /// Initiates a key with digest.
    /// This is meant to be used after the digest initiation.
    /// The key limit is 64 bytes for BLAKE2b and 32 bytes for
    /// BLAKE2s. If the limit is reached, it fails silenty by truncating
    /// key data.
    /// Params: input = Key.
    void key(scope const(ubyte)[] input)
    {
        enum MASK  = messageSize - 1;
        h[0] ^= ((input.length & MASK) << 8);
        put(input.length > messageSize ? input[0..messageSize] : input);
        c = messageSize;
    }
    
    /// Feed the algorithm with data.
    /// Also implements the $(REF isOutputRange, std,range,primitives)
    /// interface for `ubyte` and `const(ubyte)[]`.
    /// Params: input = Input data to digest
    void put(scope const(ubyte)[] input...) @trusted
    {
        // Process wordwise if properly aligned.
        if ((c | cast(size_t) input.ptr) % size_t.alignof == 0)
        {
            foreach (const word; (cast(size_t*) input.ptr)[0 .. input.length / size_t.sizeof])
            {
                if (c >= messageSize)
                {
                    t[0] += c;
                    if (t[0] < c) ++t[1]; // Overflow
                    compress;
                    c = 0;
                }
                mz.ptr[c / size_t.sizeof] = word;
                c += size_t.sizeof;
            }
            input = input.ptr[input.length - (input.length % size_t.sizeof) .. input.length];
        }
        
        // Process remainder bytewise.
        foreach (const i; input)
        {
            if (c >= messageSize)
            {
                t[0] += c;
                if (t[0] < c) ++t[1]; // Overflow
                compress;
                c = 0;
            }
            m8[c++] = i;
        }
    }
    
    /// Returns the finished hash.
    /// Returns: Raw digest data.
    ubyte[digestSizeBytes] finish()
    {
        // Final counter update
        t[0] += c;
        if (t[0] < c) ++t[1];
        
        // Zero-pad message buffer
        m8[c..$] = 0;
        v14 = ~iv[6];
        compress;
        
        // Clear out possible sensitive data
        t[0] = t[1] = c = 0; // clear size information
        mz[] = 0; // clear input message buffer
        h8[digestSizeBytes..$] = 0; // clear unused state space
        
        return h8[0..digestSizeBytes];
    }
    
private:
    
    enum digestSizeBytes = digestSize / 8;
    /// Message size in bytes.
    enum messageSize = 16 * T.sizeof;
    /// State size in bytes.
    enum stateSize = 8 * T.sizeof;
    
    union // input message buffer
    {
        size_t[messageSize / size_t.sizeof] mz = void; /// Message (m) as size_t
        T[16] m;   /// Message (m)
        ubyte[16 * T.sizeof] m8; /// Message (m) as ubyte
    }
    
    //           3 2 1 0
    // p[0] = 0x0101kknn
    // kk - Key size. Set to zero since HMAC is done elsewhere.
    // nn - Digest size in bytes.
    enum p0 = 0x0101_0000 ^ digestSizeBytes;
    union // state
    {
        T[8] h = (iv[0] ^ p0) ~ iv[1..$];
        ubyte[stateSize] h8;   /// State in byte-size
    }
    
    T[2] t;      /// Total count of input size (t).
    size_t c;          /// Counter, index for input message.
    T v14 = iv[6]; /// Vector 14. On last block, this turns from IV6 to ~IV6.
    
    void compress() @trusted
    {
        //TODO: bswap message or vectors on BigEndian platforms?
        
        T[16] v = [
            h[0],
            h[1],
            h[2],
            h[3],
            h[4],
            h[5],
            h[6],
            h[7],
            iv[0],
            iv[1],
            iv[2],
            iv[3],
            t[0] ^ iv[4],
            t[1] ^ iv[5],
            v14,
            iv[7],
        ];
        
        // Assert i=0 v[16]
        
        for (size_t round; round < ROUNDS; ++round)
        {
            immutable(ubyte) *sigma = SIGMA[round].ptr;
            
            //   a  b   c   d  x             y
            G(v, 0, 4,  8, 12, m[sigma[ 0]], m[sigma[ 1]]);
            G(v, 1, 5,  9, 13, m[sigma[ 2]], m[sigma[ 3]]);
            G(v, 2, 6, 10, 14, m[sigma[ 4]], m[sigma[ 5]]);
            G(v, 3, 7, 11, 15, m[sigma[ 6]], m[sigma[ 7]]);
            G(v, 0, 5, 10, 15, m[sigma[ 8]], m[sigma[ 9]]);
            G(v, 1, 6, 11, 12, m[sigma[10]], m[sigma[11]]);
            G(v, 2, 7,  8, 13, m[sigma[12]], m[sigma[13]]);
            G(v, 3, 4,  9, 14, m[sigma[14]], m[sigma[15]]);
            
            // Assert i=1..i=10/12 v[16]
        }
        
        h[0] ^= v[0] ^ v[8];
        h[1] ^= v[1] ^ v[9];
        h[2] ^= v[2] ^ v[10];
        h[3] ^= v[3] ^ v[11];
        h[4] ^= v[4] ^ v[12];
        h[5] ^= v[5] ^ v[13];
        h[6] ^= v[6] ^ v[14];
        h[7] ^= v[7] ^ v[15];
        
        // Assert h[8]
    }
    
    static void G(ref T[16] v, uint a, uint b, uint c, uint d, T x, T y)
    {
        v[a] = v[a] + v[b] + x;
        v[d] = ror(v[d] ^ v[a], R1);
        v[c] = v[c] + v[d];
        v[b] = ror(v[b] ^ v[c], R2);
        v[a] = v[a] + v[b] + y;
        v[d] = ror(v[d] ^ v[a], R3);
        v[c] = v[c] + v[d];
        v[b] = ror(v[b] ^ v[c], R4);
    }
}

/// Convience alias using the BLAKE2b-512 implementation.
auto blake2b_Of(T...)(T data) { return digest!(BLAKE2b512, T)(data); }
/// Alias of blake2b_Of. 
alias blake2_Of = blake2b_Of;
/// Convience alias using the BLAKE2s-256 implementation.
auto blake2s_Of(T...)(T data) { return digest!(BLAKE2s256, T)(data); }

/// Adds keyed to digest.
class WrapperDigestKeyed(T) if (isDigest!T) : WrapperDigest!T
{
    /// Initiates a key with digest.
    /// This is meant to be used after the digest initiation.
    /// The key limit is 64 bytes for BLAKE2b and 32 bytes for
    /// BLAKE2s. If the limit is reached, it fails silenty by truncating
    /// key data.
    /// Params: input = Key.
    @trusted nothrow void key(scope const(ubyte)[] input)
    {
        _digest.key(input);
    }
}

/// OOP API BLAKE2b implementation alias.
public alias BLAKE2b512Digest = WrapperDigestKeyed!BLAKE2b512;
/// OOP API BLAKE2s implementation alias.
public alias BLAKE2s256Digest = WrapperDigestKeyed!BLAKE2s256;

/// Structure conforms to the Digest API.
@safe unittest
{
    assert(isDigest!BLAKE2b512);
    assert(isDigest!BLAKE2s256);
}

/// Structure emits a blockSize field.
@safe unittest
{
    assert(hasBlockSize!BLAKE2b512);
    assert(hasBlockSize!BLAKE2s256);
}

/// Default alises digest length in Bytes.
@safe unittest
{
    assert(digestLength!BLAKE2b512 == 64);
    assert(digestLength!BLAKE2s256 == 32);
}

/// Using digest template.
@safe unittest
{
    enum TEXT = "abc";
    
    assert(blake2b_Of(TEXT) == digest!BLAKE2b512(TEXT));
    assert(blake2s_Of(TEXT) == digest!BLAKE2s256(TEXT));
}

/// Using the template API.
@system unittest
{
    import std.conv : hexString;
    
    ubyte[] s = [ 'a', 'b', 'c' ];
    
    BLAKE2s256 b2s;
    b2s.put(s);
    assert(b2s.finish() == cast(ubyte[])hexString!(
        "508c5e8c327c14e2e1a72ba34eeb452f37458b209ed63a294d999b4c86675982"));
}

/// Using convenience aliases.
@safe unittest
{
    assert(toHexString!(LetterCase.lower)(blake2b_Of("")) ==
        "786a02f742015903c6c6fd852552d272912f4740e15847618a86e217f71f5419"~
        "d25e1031afee585313896444934eb04b903a685b1448b755d56f701afe9be2ce");
    assert(toHexString!(LetterCase.lower)(blake2s_Of("")) ==
        "69217a3079908094e11121d042354a7c1f55b6482ca1a51e1b250dfd1ed0eef9");
}

/// Using convenience aliases on "abc".
@safe unittest
{
    assert(toHexString!(LetterCase.lower)(blake2b_Of("abc")) ==
        "ba80a53f981c4d0d6a2797b69f12f6e94c212f14685ac4b74b12bb6fdbffa2d1"~
        "7d87c5392aab792dc252d5de4533cc9518d38aa8dbf1925ab92386edd4009923");
    assert(toHexString!(LetterCase.lower)(blake2s_Of("abc")) ==
        "508c5e8c327c14e2e1a72ba34eeb452f37458b209ed63a294d999b4c86675982");
}


/// Using the template API to hash one million 'a'.
@system unittest
{
    import std.conv : hexString;
    
    ubyte[] onemilliona = new ubyte[1_000_000];
    onemilliona[] = 'a';
    
    BLAKE2b512 b2b;
    b2b.put(onemilliona);
    assert(b2b.finish() == cast(ubyte[]) hexString!(
        "98fb3efb7206fd19ebf69b6f312cf7b64e3b94dbe1a17107913975a793f177e1"~
        "d077609d7fba363cbba00d05f7aa4e4fa8715d6428104c0a75643b0ff3fd3eaf"));
    
    BLAKE2s256 b2s;
    b2s.put(onemilliona);
    assert(b2s.finish() == cast(ubyte[]) hexString!(
        "bec0c0e6cde5b67acb73b81f79a67a4079ae1c60dac9d2661af18e9f8b50dfa5"));
}

/// Using the OOP API.
@system unittest
{
    import std.conv : hexString;
    
    ubyte[] s = ['a', 'b', 'c'];
    
    Digest b2b = new BLAKE2b512Digest();
    b2b.put(s);
    assert(b2b.finish() == cast(ubyte[]) hexString!(
        "ba80a53f981c4d0d6a2797b69f12f6e94c212f14685ac4b74b12bb6fdbffa2d1"~
        "7d87c5392aab792dc252d5de4533cc9518d38aa8dbf1925ab92386edd4009923"));
    
    Digest b2s = new BLAKE2s256Digest();
    b2s.put(s);
    assert(b2s.finish() == cast(ubyte[]) hexString!(
        "508c5e8c327c14e2e1a72ba34eeb452f37458b209ed63a294d999b4c86675982"));
}

/// Template API delegate.
@system unittest
{
    import std.conv : hexString;
    
    // NOTE: Because the digest is a structure, it must be passed by reference.
    void doSomething(T)(ref T hash)
        if (isDigest!T)
        {
            hash.put([ 'a', 'b', 'c' ]);
        }
    BLAKE2b512 b2b;
    b2b.start();
    doSomething(b2b);
    assert(b2b.finish() == cast(ubyte[]) hexString!(
        "ba80a53f981c4d0d6a2797b69f12f6e94c212f14685ac4b74b12bb6fdbffa2d1"~
        "7d87c5392aab792dc252d5de4533cc9518d38aa8dbf1925ab92386edd4009923"));
    BLAKE2s256 b2s;
    b2s.start();
    doSomething(b2s);
    assert(b2s.finish() == cast(ubyte[]) hexString!(
        "508c5e8c327c14e2e1a72ba34eeb452f37458b209ed63a294d999b4c86675982"));
}

/// Keying digests at run-time using Template API.
@system unittest
{
    // NOTE: This implementation is not yet compatible with the hmac/HMAC
    //       templates at the moment.
    
    import std.ascii : LetterCase;
    import std.string : representation;
    import std.conv : hexString;
    
    auto secret2b = hexString!(
        "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"~
        "202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f")
        .representation;
    auto secret2s = hexString!(
        "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
        .representation;
    immutable(ubyte)[] data = hexString!("000102").representation;
    
    BLAKE2b512 b2b;
    b2b.key(secret2b);
    b2b.put(data);
    assert(b2b.finish().toHexString!(LetterCase.lower) ==
        "33d0825dddf7ada99b0e7e307104ad07ca9cfd9692214f1561356315e784f3e5"~
        "a17e364ae9dbb14cb2036df932b77f4b292761365fb328de7afdc6d8998f5fc1",
        "BLAKE2b secret failed");
    
    BLAKE2s256 b2s;
    b2s.key(secret2s);
    b2s.put(data);
    assert(b2s.finish().toHexString!(LetterCase.lower) ==
        "1d220dbe2ee134661fdf6d9e74b41704710556f2f6e5a091b227697445dbea6b",
        "BLAKE2s secret failed");
}

/// Keying digests at run-time using OOP API.
@system unittest
{
    import std.ascii : LetterCase;
    import std.string : representation;
    import std.conv : hexString;
    
    enum secret2b = cast(ubyte[])hexString!(
        "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"~
        "202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f");
    enum secret2s = cast(ubyte[])hexString!(
        "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
    auto data = hexString!("000102").representation;
    
    BLAKE2b512Digest b2b = new BLAKE2b512Digest();
    b2b.key(secret2b);
    b2b.put(data);
    assert(b2b.finish().toHexString!(LetterCase.lower) ==
        "33d0825dddf7ada99b0e7e307104ad07ca9cfd9692214f1561356315e784f3e5"~
        "a17e364ae9dbb14cb2036df932b77f4b292761365fb328de7afdc6d8998f5fc1",
        "BLAKE2b secret failed");
    
    BLAKE2s256Digest b2s = new BLAKE2s256Digest();
    b2s.key(secret2s);
    b2s.put(data);
    assert(b2s.finish().toHexString!(LetterCase.lower) ==
        "1d220dbe2ee134661fdf6d9e74b41704710556f2f6e5a091b227697445dbea6b",
        "BLAKE2s secret failed");
}
