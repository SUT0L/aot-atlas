using System.Buffers.Binary;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using Atlas;
using Atlas.Binja;

internal static unsafe class FrozenTypeChecks {
    internal static void Run(ReadOnlySpan<string> binaries) {
        Assert(sizeof(StructureMember) == 32);
        byte empty = 0;
        BoolConfidence signed = new() { Value = 1, Confidence = 255 }, unsigned = new() { Confidence = 255 }, qualifier = default;
        nint integer = Core.BNCreateIntegerType(4, &signed, &empty);
        nint character = Core.BNCreateWideCharType(2, &empty);
        nint octet = Core.BNCreateIntegerType(1, &unsigned, &empty);
        var byteType = new TypeConfidence(octet);
        nint pointer = Core.BNCreatePointerTypeOfWidth(8, &byteType, &qualifier, &qualifier, 0);

        var matrix = new FrozenObject { Kind = FrozenKind.Array, Offset = 8, Count = 6, AllocationSize = 64, Data = new IndexRange(40, 24) };
        var matrixTable = new MethodTable { Flags = 0xDC020004, BaseSize = 40 };
        nint matrixType = ObjectTypes.Sequence(matrix, matrixTable, integer, pointer, integer);
        Check(matrixType, matrix, matrixTable);
        Core.BNFreeType(matrixType);

        Span<double> cached = stackalloc double[5];
        Span<double> uncached = stackalloc double[5];

        foreach (string binary in binaries) {
            var image = new PeImage(File.ReadAllBytes(binary));
            var header = ReadyToRun.Read(image);
            var section = header.Find(313);
            var metadata = new Metadata(section.Length == 0 ? default : image.FileMemory(section.Start, checked((int)section.Length)),
                header.MetadataHandleBits, header.Major < 10);
            metadata.ReadDefinitions();
            var fixups = RuntimeTables.Fixups(image, header.Find(308));
            var maps = new ReflectionMaps();
            maps.Read(image, header, metadata, fixups, MapFormat.Auto);
            var extraction = new Extraction(image, header, metadata, maps, fixups);
            var objects = CollectionsMarshal.AsSpan(extraction.Frozen.Objects);
            var tables = CollectionsMarshal.AsSpan(extraction.Types.Types);
            var elements = new Dictionary<int, nint>();
            var shapes = new Dictionary<(int Type, int Count), nint>();
            int sequences = 0, boxes = 0;

            foreach (ref readonly var entry in objects) {
                if (entry.Kind == FrozenKind.Object)
                    continue;

                ref readonly var table = ref tables[entry.TypeIndex];
                int width = entry.Kind == FrozenKind.Box ? checked((int)table.ValueSize) : table.ComponentSize;
                if (entry.Kind != FrozenKind.String && !elements.ContainsKey(width))
                    elements.Add(width, Core.BNCreateArrayType(&byteType, (uint)width));

                if (shapes.ContainsKey((entry.TypeIndex, entry.Count)))
                    continue;
                nint type = entry.Kind == FrozenKind.Box
                    ? ObjectTypes.Box(table.BaseSize - 8, elements[width], pointer)
                    : ObjectTypes.Sequence(entry, table, entry.Kind == FrozenKind.String ? character : elements[width], pointer, integer);
                Check(type, entry, table);
                shapes.Add((entry.TypeIndex, entry.Count), type);
                if (entry.Kind == FrozenKind.Box)
                    ++boxes;
                else
                    ++sequences;
            }

            foreach (nint type in shapes.Values)
                Core.BNFreeType(type);
            shapes.Clear();
            ulong expectedWidth = 0;
            foreach (ref readonly var entry in objects) {
                if (entry.Kind != FrozenKind.Object)
                    expectedWidth += (uint)entry.AllocationSize - 8;
            }

            // Background GC discards unused allocation contexts, which this counter counts as allocated bytes
            // Keep collections outside this measurement so it counts the construction loops managed allocations
            Assert(GC.TryStartNoGCRegion(1024 * 1024));
            try {
                for (int trial = 0; trial < 10; ++trial) {
                    bool reuse = (trial & 1) != 0;
                    ulong total = 0;
                    long allocated = GC.GetAllocatedBytesForCurrentThread();
                    long started = Stopwatch.GetTimestamp();
                    foreach (ref readonly var entry in objects) {
                        if (entry.Kind == FrozenKind.Object)
                            continue;
                        var key = (entry.TypeIndex, entry.Count);
                        nint existing = 0;
                        if (!reuse || !shapes.TryGetValue(key, out existing)) {
                            ref readonly var table = ref tables[entry.TypeIndex];
                            nint type = entry.Kind == FrozenKind.Box
                                ? ObjectTypes.Box(table.BaseSize - 8, elements[checked((int)table.ValueSize)], pointer)
                                : ObjectTypes.Sequence(entry, table, entry.Kind == FrozenKind.String ? character : elements[table.ComponentSize], pointer, integer);
                            total += Inspect.BNGetTypeWidth(type);
                            if (reuse)
                                shapes.Add(key, type);
                            else
                                Core.BNFreeType(type);
                        } else {
                            total += Inspect.BNGetTypeWidth(existing);
                        }
                    }
                    if (reuse)
                        cached[trial / 2] = Stopwatch.GetElapsedTime(started).TotalMilliseconds;
                    else
                        uncached[trial / 2] = Stopwatch.GetElapsedTime(started).TotalMilliseconds;
                    long allocatedBytes = GC.GetAllocatedBytesForCurrentThread() - allocated;
                    if (allocatedBytes != 0)
                        throw new InvalidDataException($"Frozen construction allocated {allocatedBytes} bytes in {binary}, trial {trial}, cached {reuse}.");
                    Assert(total == expectedWidth);
                    foreach (nint type in shapes.Values)
                        Core.BNFreeType(type);
                    shapes.Clear();
                }
            } finally {
                GC.EndNoGCRegion();
            }

            cached.Sort();
            uncached.Sort();
            Console.WriteLine($"Input SHA-256: {Convert.ToHexStringLower(SHA256.HashData(image.FileData))}");
            Console.WriteLine($"{Path.GetFileName(binary)} ({Path.GetFileName(Path.GetDirectoryName(binary))}): {objects.Length} objects, {sequences} sequence and {boxes} boxed layouts; core construction median uncached {uncached[2]:F3} ms, cached {cached[2]:F3} ms.");
            foreach (nint element in elements.Values)
                Core.BNFreeType(element);
        }

        byte[] codeUnits = new byte[65536 * 2];
        for (int i = 0; i < 65536; ++i)
            BinaryPrimitives.WriteUInt16LittleEndian(codeUnits.AsSpan(i * 2), (ushort)i);
        byte[] quoted = new byte[65536 * 6 + 10];
        quoted.AsSpan().Fill(0xA5);
        int length = FrozenText.Quote(codeUnits, quoted.AsSpan(0, quoted.Length - 8));
        Assert(quoted.AsSpan(length).IndexOfAnyExcept((byte)0xA5) < 0);
        File.WriteAllBytes(Path.Combine(AppContext.BaseDirectory, "utf16-code-units.json"), quoted.AsSpan(0, length));
        Console.WriteLine("UTF-16: all 65536 code units emitted without writing beyond the quoted value.");

        Core.BNFreeType(pointer);
        Core.BNFreeType(octet);
        Core.BNFreeType(character);
        Core.BNFreeType(integer);
    }

    private static void Check(nint type, in FrozenObject entry, in MethodTable table) {
        Assert(Inspect.BNGetTypeWidth(type) == (uint)entry.AllocationSize - 8);
        nint structure = Inspect.BNGetTypeStructure(type);
        Assert(Inspect.BNIsStructurePacked(structure) != 0);
        nuint count = 0;
        StructureMember* members = Inspect.BNGetStructureMembers(structure, &count);
        bool matrix = entry.Kind == FrozenKind.Array && table.ElementType == 0x17;
        Assert(count == (entry.Kind == FrozenKind.Box ? 2U : matrix ? 5U : 3U));
        for (nuint i = 0; i < count; ++i) {
            ref readonly var member = ref members[i];
            string name = Marshal.PtrToStringUTF8(member.Name)!;
            Assert(member.Confidence == 255);
            ulong width = Inspect.BNGetTypeWidth(member.Type);
            if (name == "method_table") {
                Assert(member.Offset == 0 && width == 8);
            } else if (name == "length") {
                Assert(member.Offset == 8 && width == 4);
            } else if (name == "payload") {
                Assert(member.Offset == 8 && width == table.ValueSize);
            } else if (name is "elements" or "chars") {
                Assert(member.Offset == (uint)(entry.Data.Start - entry.Offset));
                Assert(width == (uint)entry.Data.Count + (entry.Kind == FrozenKind.String ? 2U : 0));
                Assert(Inspect.BNGetTypeElementCount(member.Type) == (uint)entry.Count + (entry.Kind == FrozenKind.String ? 1U : 0));
            } else {
                uint rank = (table.BaseSize - 24) / 8;
                Assert(matrix && (name is "dimensions" or "lower_bounds"));
                Assert(member.Offset == (name == "dimensions" ? 16U : 16 + rank * 4) && width == rank * 4);
            }
        }

        Inspect.BNFreeStructureMemberList(members, count);
        Core.BNFreeStructure(structure);
    }

    private static void Assert(bool condition) {
        if (!condition)
            throw new InvalidDataException("Binary Ninja's frozen layout differs from the runtime allocation.");
    }
}

[StructLayout(LayoutKind.Sequential)]
internal struct StructureMember {
    internal nint Type, Name;
    internal ulong Offset;
    internal byte Confidence, Access, Scope, BitPosition, BitWidth;
}

internal static unsafe partial class Inspect {
    [LibraryImport("binaryninjacore")] internal static partial nint BNGetTypeStructure(nint type);
    [LibraryImport("binaryninjacore")] internal static partial byte BNIsStructurePacked(nint structure);
    [LibraryImport("binaryninjacore")] internal static partial StructureMember* BNGetStructureMembers(nint structure, nuint* count);
    [LibraryImport("binaryninjacore")] internal static partial void BNFreeStructureMemberList(StructureMember* members, nuint count);
    [LibraryImport("binaryninjacore")] internal static partial ulong BNGetTypeElementCount(nint type);
}
