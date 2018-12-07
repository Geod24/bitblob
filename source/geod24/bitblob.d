/*******************************************************************************

    Variadic-sized value type to represent a hash

    A `BitBlob` is a value type representing a hash.
    The argument is the size in bits, e.g. for sha256 it is 256.
    It can be initialized from the hexadecimal string representation
    or an `ubyte[]`, making it easy to interact with `std.digest`

    Author:         Mathias 'Geod24' Lang
    License:        MIT (See LICENSE.txt)
    Copyright:      Copyright (c) 2017-2018 Mathias Lang. All rights reserved.

*******************************************************************************/

module geod24.bitblob;

static import std.ascii;
import std.algorithm;
import std.range;
import std.format;
import std.utf;

///
@nogc @safe pure nothrow unittest
{
    import std.digest.sha;
    alias Hash = BitBlob!256;
    Hash k1 = sha256Of("Hello World");
}

/*******************************************************************************

    A value type representing a hash

    Params:
      Bits = The size of the hash, in bits. Must be a multiple of 8.

*******************************************************************************/
public struct BitBlob (size_t Bits)
{
    /// Used by std.format
    /// Cannot be `nothrow @nogc` since sformat is not, but does not allocate
    public void toString (scope void delegate(const(char)[]) @safe sink) const @safe
    {
        sink("0x");
        char[2] data;
        // retro because the data is stored in little endian
        this.data[].retro.each!(
            (bin)
            {
                sformat(data, "%0.2x", bin);
                sink(data);
            });
    }

    /// Used for serialization
    public string toString () const @safe
    {
        size_t idx;
        char[Width * 2 + 2] buffer = void;
        scope sink = (const(char)[] v) {
                buffer[idx .. idx + v.length] = v;
                idx += v.length;
            };
        this.toString(sink);
        return buffer.idup;
    }

    pure nothrow @nogc @safe:

    /***************************************************************************

        Create a BitBlob from binary data, e.g. serialized data

        Params:
            bin  = Binary data to store in this `BitBlob`.
            isLE = `true` if the data is little endian, `false` otherwise.
                   Internally the data will be stored in little endian.

        Throws:
            If `bin.length != typeof(this).Width`

    ***************************************************************************/

    public this (scope const ubyte[] bin, bool isLE = true)
    {
        assert(bin.length == Width);
        this.data[] = bin[];
        if (!isLE)
            this.data[].reverse;
    }

    /***************************************************************************

        Create a BitBlob from an hexadecimal string representation

        Params:
            hexstr = String representation of the binary data in base 16.
                     The hexadecimal prefix (0x) is optional.
                     Can be upper or lower case.

        Throws:
            If `hexstr_without_prefix.length != (typeof(this).Width * 2)`.

    ***************************************************************************/

    public this (scope const(char)[] hexstr)
    {
        assert(hexstr.length == (Width * 2)
               || hexstr.length == (Width * 2) + "0x".length);

        auto range = hexstr.byChar.map!(std.ascii.toLower!(char));
        range.skipOver("0x".byChar);
        // Each doesn't work
        foreach (size_t idx, chunk; range.map!(fromHex).chunks(2).retro.enumerate)
            this.data[idx] = cast(ubyte)((chunk[0] << 4) + chunk[1]);
    }

    /// Used for deserialization
    static auto fromString (const(char)[] str)
    {
        return BitBlob!(Bits)(str);
    }

    static assert (
        Bits % 8 == 0,
        "Argument to BitBlob must be a multiple of 8");

    /// The width of this aggregate, in octets
    public static immutable Width = Bits / 8;

    /// Store the internal data
    private ubyte[Width] data;

    /// Returns: If this BitBlob has any value
    public bool isNull () const
    {
        return this.data[].all!((v) => v == 0);
    }

    /// Used for sha256Of
    public const(ubyte)[] opIndex () const
    {
        return this.data;
    }

    /// Public because of a visibility bug
    public static ubyte fromHex (char c)
    {
        if (c >= '0' && c <= '9')
            return cast(ubyte)(c - '0');
        if (c >= 'a' && c <= 'f')
            return cast(ubyte)(10 + c - 'a');
        assert(0, "Unexpected char in string passed to BitBlob");
    }

    public int opCmp (ref const typeof(this) s) const
    {
        // Reverse because little endian
        foreach_reverse (idx, b; this.data)
            if (b != s.data[idx])
                return b - s.data[idx];
        return 0;
    }
}

pure @safe nothrow @nogc unittest
{
    alias Hash = BitBlob!256;

    Hash gen1 = GenesisBlockHashStr;
    Hash gen2 = GenesisBlockHash;
    assert(gen1.data == GenesisBlockHash);
    assert(gen1 == gen2);

    Hash gm1 = GMerkle_str;
    Hash gm2 = GMerkle_bin;
    assert(gm1.data == GMerkle_bin);
    assert(gm1 == gm2);

    Hash empty;
    assert(empty.isNull);
    assert(!gen1.isNull);

    // Test opCmp
    assert(empty < gen1);
    assert(gm1 > gen2);
}

/// Test toString
unittest
{
    import std.format;
    alias Hash = BitBlob!256;
    Hash gen1 = GenesisBlockHashStr;
    assert(format("%s", gen1) == GenesisBlockHashStr);
}

version (unittest)
{
private:
    /// Bitcoin's genesis block hash
    static immutable GenesisBlockHashStr =
        "0x000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f";
    static immutable ubyte[32] GenesisBlockHash = [
        0x6f, 0xe2, 0x8c, 0x0a, 0xb6, 0xf1, 0xb3, 0x72, 0xc1, 0xa6, 0xa2, 0x46,
        0xae, 0x63, 0xf7, 0x4f, 0x93, 0x1e, 0x83, 0x65, 0xe1, 0x5a, 0x08, 0x9c,
        0x68, 0xd6, 0x19, 0x00, 0x00, 0x00, 0x00, 0x00 ];

    /// Bitcoin's genesis block Merkle root hash
    static immutable GMerkle_str =
        "0X4A5E1E4BAAB89F3A32518A88C31BC87F618F76673E2CC77AB2127B7AFDEDA33B";
    static immutable ubyte[] GMerkle_bin = [
        0x3b, 0xa3, 0xed, 0xfd, 0x7a, 0x7b, 0x12, 0xb2, 0x7a, 0xc7, 0x2c, 0x3e,
        0x67, 0x76, 0x8f, 0x61, 0x7f, 0xc8, 0x1b, 0xc3, 0x88, 0x8a, 0x51, 0x32,
        0x3a, 0x9f, 0xb8, 0xaa, 0x4b, 0x1e, 0x5e, 0x4a ];
}
