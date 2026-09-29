using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text.Json;

internal static partial class Program {
    private static int completed;

    [LibraryImport("kernel32.dll")]
    private static partial nint GetModuleHandleW(nint name);

    [LibraryImport("ntdll.dll")]
    private static partial nint RtlLookupFunctionEntry(ulong pc, out ulong imageBase, nint history);

    private static unsafe void Main(string[] args) {
        using var document = JsonDocument.Parse(File.ReadAllBytes(args[0]));
        var data = document.RootElement;
        string digest = Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(Environment.ProcessPath!))).ToLowerInvariant();
        Assert(data.GetProperty("input_sha256").GetString() == digest);
        ulong module = (ulong)GetModuleHandleW(0);
        var entries = data.GetProperty("entries").EnumerateArray().ToDictionary(entry => entry.GetProperty("rva").GetUInt32());
        int count = data.GetProperty("directory_count").GetInt32();
        int lookups = 0;
        foreach (var entry in data.GetProperty("entries").EnumerateArray().Take(count)) {
            uint begin = entry.GetProperty("begin").GetUInt32(), end = entry.GetProperty("end").GetUInt32();
            var expected = entry;
            while (expected.GetProperty("indirect").GetBoolean())
                expected = entries[expected.GetProperty("parent").GetUInt32()];

            for (int sample = 0; sample < 3; ++sample) {
                uint pc = sample == 0 ? begin : sample == 1 ? begin + (end - begin) / 2 : end - 1;
                uint* actual = (uint*)RtlLookupFunctionEntry(module + pc, out ulong imageBase, 0);
                Assert(actual != null && imageBase == module);
                Assert(actual[0] == expected.GetProperty("begin").GetUInt32());
                Assert(actual[1] == expected.GetProperty("end").GetUInt32());
                Assert(actual[2] == expected.GetProperty("unwind").GetUInt32());
                ++lookups;
            }
        }

        foreach (var entry in entries.Values) {
            uint* live = (uint*)(module + entry.GetProperty("rva").GetUInt32());
            Assert(live[0] == entry.GetProperty("begin").GetUInt32());
            Assert(live[1] == entry.GetProperty("end").GetUInt32());
            Assert(live[2] == entry.GetProperty("unwind").GetUInt32());
        }
        int records = 0;
        foreach (var info in data.GetProperty("unwind_info").EnumerateArray()) {
            byte[] expected = Convert.FromHexString(info.GetProperty("bytes").GetString()!);
            var actual = new ReadOnlySpan<byte>((void*)(module + info.GetProperty("rva").GetUInt32()), expected.Length);
            Assert(actual.SequenceEqual(expected));
            ++records;
        }

        Assert(Guard(0) + Guard(1) + Guard(2) == 19 && completed == 3);
        delegate* unmanaged<int, int> reverse = &Reverse;
        Assert(reverse(4) == 5);
        Console.WriteLine($"{count} runtime functions, {lookups} Windows lookups, {records} live unwind records matched; {digest}");
    }

    [MethodImpl(MethodImplOptions.NoInlining)]
    private static int Guard(int value) {
        try {
            if (value == 1)
                throw new InvalidOperationException();
            return value + 3;
        } catch (InvalidOperationException) when (value == 1) {
            return 11;
        } finally {
            ++completed;
        }
    }

    [UnmanagedCallersOnly]
    private static int Reverse(int value) => value + 1;

    private static void Assert(bool condition) {
        if (!condition)
            throw new InvalidDataException("Live Windows unwind lookup disagrees with the extracted records.");
    }
}
