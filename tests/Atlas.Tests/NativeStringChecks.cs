using System.Text;
using Atlas;

internal static class NativeStringChecks {
    private const ulong Base = 0x140001000;

    internal static void Run() {
        var strings = Scan("Alpha\0"u8.ToArray());
        Assert(strings.Items.SequenceEqual([new NativeString(0x1000, new IndexRange(512, 5), false)]));
        strings = Scan(Encoding.Unicode.GetBytes("Wide\0"));
        Assert(strings.Items.SequenceEqual([new NativeString(0x1000, new IndexRange(512, 8), true)]));
        Assert(Scan("Unterminated"u8.ToArray()).Items.Count == 0);
        Assert(Scan("Short\0\x01Tail\0"u8.ToArray()).Items.Count == 1);
        Assert(Scan("Line\nText\0"u8.ToArray()).Items.Single().Data.Count == 9);
        strings = Scan("\0abcd\0e\0f\0g\0\0\0"u8.ToArray());
        Assert(strings.Items.SequenceEqual([
            new NativeString(0x1001, new IndexRange(513, 4), false),
            new NativeString(0x1004, new IndexRange(516, 8), true)]));

        strings = Scan("Excluded\0Tail\0"u8.ToArray(), [new RtrSection(313, 0, Base, 9)]);
        Assert(strings.Items.SequenceEqual([new NativeString(0x1009, new IndexRange(521, 4), false)]));
        Assert(Scan("Crosses\0"u8.ToArray(), [new RtrSection(313, 0, Base + 4, 4)]).Items.Count == 0);
        Assert(Scan(Encoding.Unicode.GetBytes("Crosses\0"), [new RtrSection(313, 0, Base + 7, 9)]).Items.Count == 0);
        strings = Scan("First\0Middle\0Last\0"u8.ToArray(), [new RtrSection(313, 0, Base + 9, 4), new RtrSection(314, 0, Base + 6, 5)]);
        Assert(strings.Items.Select(item => item.Rva).SequenceEqual([0x1000U, 0x100DU]));
        Assert(strings.ScannedBytes == 11);

        byte[] large = new byte[4 * 1024 * 1024 + 24];
        Encoding.Unicode.GetBytes("Large\0").CopyTo(large.AsSpan(4 * 1024 * 1024 + 8));
        strings = Scan(large);
        Assert(strings.Items.SequenceEqual([new NativeString(0x401008, new IndexRange(0x400208, 10), true)]));
        Assert(strings.ScannedBytes == large.Length);
        Console.WriteLine("Native strings: ASCII, UTF-16, controls, termination, exclusion boundaries and a region over 4 MiB passed.");
    }

    private static NativeStrings Scan(byte[] data, RtrSection[]? excluded = null) =>
        new(PeFixture.Create(data, ".rdata", 0x40000040), excluded);

    private static void Assert(bool condition) {
        if (!condition)
            throw new Exception("Native string assertion failed.");
    }
}
