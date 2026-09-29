using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using Atlas;
using Atlas.Binja;

internal static unsafe class UnwindTypeChecks {
    internal static void Run(ReadOnlySpan<string> binaries) {
        byte empty = 0;
        BoolConfidence unsigned = new() { Confidence = 255 };
        nint u8 = Core.BNCreateIntegerType(1, &unsigned, &empty);
        nint u16 = Core.BNCreateIntegerType(2, &unsigned, &empty);
        nint u32 = Core.BNCreateIntegerType(4, &unsigned, &empty);
        nint entry = UnwindTypes.Entry(u32);
        Check(entry, 12, [("begin_rva", 0, 4), ("end_rva", 4, 4), ("unwind_data", 8, 4)]);
        var expected = new List<(string Name, ulong Offset, ulong Width)>(6);
        for (int tail = 0; tail < 3; ++tail) {
            for (int slots = 0; slots <= byte.MaxValue; ++slots) {
                UnwindInfo info = new() { SlotCount = (byte)slots, VersionFlags = (byte)(1 | (tail == 2 ? 32 : tail == 1 ? 8 : 0)) };
                info.Length = checked((ushort)(tail == 0 ? 4 + slots * 2 : info.TailOffset + (tail == 1 ? 4 : 12)));
                nint type = UnwindTypes.Info(info, u8, u16, u32, entry);
                expected.Clear();
                expected.Add(("version_flags", 0, 1));
                expected.Add(("prolog_size", 1, 1));
                expected.Add(("slot_count", 2, 1));
                expected.Add(("frame_register_offset", 3, 1));
                if (slots != 0)
                    expected.Add(("codes", 4, (uint)slots * 2));
                if (tail != 0)
                    expected.Add((tail == 1 ? "handler_rva" : "chained_function", (uint)info.TailOffset, tail == 1 ? 4U : 12U));

                Check(type, info.Length, CollectionsMarshal.AsSpan(expected));
                Core.BNFreeType(type);
            }
        }
        Console.WriteLine("BN6 unwind types: all 768 slot-count/tail layouts retain exact widths, names and offsets.");

        Span<double> parseTimes = stackalloc double[7], uncached = stackalloc double[5], cached = stackalloc double[5];
        nint[] shapes = new nint[768];
        foreach (string binary in binaries) {
            var image = new PeImage(File.ReadAllBytes(binary));
            var tables = new UnwindTables(image);
            for (int i = 0; i < parseTimes.Length; ++i) {
                long start = Stopwatch.GetTimestamp();
                var result = new UnwindTables(image);
                parseTimes[i] = Stopwatch.GetElapsedTime(start).TotalMilliseconds;
                Assert(result.DirectoryCount == tables.DirectoryCount && result.Infos.Count == tables.Infos.Count);
            }
            parseTimes.Sort();

            int unique = 0;
            for (int sample = 0; sample < 5; ++sample) {
                long start = Stopwatch.GetTimestamp();
                foreach (ref readonly var info in CollectionsMarshal.AsSpan(tables.Infos)) {
                    nint type = UnwindTypes.Info(info, u8, u16, u32, entry);
                    Core.BNFreeType(type);
                }
                uncached[sample] = Stopwatch.GetElapsedTime(start).TotalMilliseconds;

                unique = 0;
                start = Stopwatch.GetTimestamp();
                foreach (ref readonly var info in CollectionsMarshal.AsSpan(tables.Infos)) {
                    int tail = (info.Flags & 4) != 0 ? 2 : (info.Flags & 3) != 0 ? 1 : 0;
                    int key = tail * 256 + info.SlotCount;
                    if (shapes[key] == 0) {
                        shapes[key] = UnwindTypes.Info(info, u8, u16, u32, entry);
                        ++unique;
                    }
                }
                foreach (nint type in shapes) {
                    if (type != 0)
                        Core.BNFreeType(type);
                }
                cached[sample] = Stopwatch.GetElapsedTime(start).TotalMilliseconds;
                shapes.AsSpan().Clear();
            }
            uncached.Sort();
            cached.Sort();
            string digest = Convert.ToHexStringLower(SHA256.HashData(image.FileData));
            Console.WriteLine($"Unwind {digest}: {tables.DirectoryCount} runtime functions, {tables.Infos.Count} records; parse {parseTimes[3]:F3} ms, native types uncached {uncached[2]:F3} ms, {unique} cached shapes {cached[2]:F3} ms.");
        }
        Core.BNFreeType(entry);
        Core.BNFreeType(u32);
        Core.BNFreeType(u16);
        Core.BNFreeType(u8);
    }

    private static void Check(nint type, ulong width, ReadOnlySpan<(string Name, ulong Offset, ulong Width)> expected) {
        nint copy = Core.BNNewTypeReference(type);
        Assert(Core.BNGetTypeWidth(copy) == width);
        nint structure = Inspect.BNGetTypeStructure(copy);
        Assert(Inspect.BNIsStructurePacked(structure) != 0);
        nuint count = 0;
        var members = Inspect.BNGetStructureMembers(structure, &count);
        Assert(count == (uint)expected.Length);
        for (int i = 0; i < (int)count; ++i) {
            var member = members[i];
            Assert(Marshal.PtrToStringUTF8(member.Name) == expected[i].Name);
            Assert(member.Offset == expected[i].Offset && Core.BNGetTypeWidth(member.Type) == expected[i].Width);
            byte kind = expected[i].Name == "chained_function" ? (byte)4 : expected[i].Name == "codes" ? (byte)7 : (byte)2;
            Assert(Inspect.BNGetTypeClass(member.Type) == kind);
        }
        Inspect.BNFreeStructureMemberList(members, count);
        Core.BNFreeStructure(structure);
        Core.BNFreeType(copy);
    }

    private static void Assert(bool condition) {
        if (!condition)
            throw new InvalidDataException("Native unwind types disagree with the Windows record layout.");
    }
}
