/// Throughput benchmark for blake2-d.
///
/// Run with: dub run blake2-d:bench -b release-nobounds
module bench;

import std.datetime.stopwatch : StopWatch, AutoStart;
import std.digest : digest, digestLength;
import std.stdio : writefln;
import blake2d;

/// Amount of data to feed per measurement.
enum size_t TOTAL = 256 * 1024 * 1024; // 256 MiB

void bench(H)(string name, const(ubyte)[] buffer)
{
    size_t rounds = TOTAL / buffer.length;

    H hash;
    hash.start();

    StopWatch sw = StopWatch(AutoStart.yes);
    foreach (i; 0 .. rounds)
        hash.put(buffer);
    ubyte[digestLength!H] result = hash.finish();
    sw.stop();

    double secs = sw.peek.total!"usecs" / 1_000_000.0;
    double mibs = (cast(double)(rounds * buffer.length) / (1024 * 1024)) / secs;
    writefln("%-24s buf=%6d  %8.1f MiB/s", name, buffer.length, mibs);
}

void main()
{
    ubyte[] buffer = new ubyte[64 * 1024];
    foreach (i, ref b; buffer)
        b = cast(ubyte) i;

    // Sanity: chunked feeding at awkward sizes over an unaligned base slice
    // must match the one-shot digest. Plain asserts are compiled out in
    // release builds, so compare and use assert(0), which always stays.
    ubyte[] data = buffer[1 .. 4097];
    foreach (chunk; [1, 3, 7, 63, 64, 65, 127, 128, 129, 1000])
    {
        BLAKE2b512 b2b;
        BLAKE2s256 b2s;
        for (size_t i; i < data.length; i += chunk)
        {
            size_t end = i + chunk > data.length ? data.length : i + chunk;
            b2b.put(data[i .. end]);
            b2s.put(data[i .. end]);
        }
        if (b2b.finish() != digest!BLAKE2b512(data))
            assert(0, "BLAKE2b chunked digest mismatch");
        if (b2s.finish() != digest!BLAKE2s256(data))
            assert(0, "BLAKE2s chunked digest mismatch");
    }

    bench!BLAKE2b512("BLAKE2b-512", buffer);
    bench!BLAKE2s256("BLAKE2s-256", buffer);
    bench!BLAKE2b512("BLAKE2b-512", buffer[0 .. 128]);
    bench!BLAKE2s256("BLAKE2s-256", buffer[0 .. 128]);
    bench!BLAKE2b512("BLAKE2b-512 (unaligned)", buffer[1 .. 129]);
    bench!BLAKE2s256("BLAKE2s-256 (unaligned)", buffer[1 .. 129]);
}
