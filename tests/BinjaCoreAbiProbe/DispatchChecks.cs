using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text.Json;
using Atlas;
using Atlas.Binja;

internal static unsafe class DispatchChecks {
    internal static void Run(ReadOnlySpan<string> binaries) {
        byte empty = 0;
        BoolConfidence unsigned = new() { Confidence = 255 };
        nint integer = Core.BNCreateIntegerType(2, &unsigned, &empty);
        nint instance = DispatchTypes.Entry(integer, false), statics = DispatchTypes.Entry(integer, true);
        CheckEntry(instance, false);
        CheckEntry(statics, true);
        var mixed = new DispatchMap { StandardCount = 2, DefaultCount = 3, StaticCount = 5, StaticDefaultCount = 7 };
        nint mixedType = DispatchTypes.Map(mixed, integer, instance, statics);
        CheckMap(mixedType, mixed);
        Core.BNFreeType(mixedType);

        Span<double> cached = stackalloc double[5], uncached = stackalloc double[5];
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
            string digest = Convert.ToHexStringLower(SHA256.HashData(image.FileData));
            long started = Stopwatch.GetTimestamp();
            var records = new DispatchRecords(extraction);
            double prepareMs = Stopwatch.GetElapsedTime(started).TotalMilliseconds;
            byte[] buffer = new byte[records.BufferLength + 8];
            long expectedLength = 0;
            using var stream = File.Create(Path.Combine(AppContext.BaseDirectory, $"dispatch-{digest[..12]}.json"));
            using var json = new Utf8JsonWriter(stream);
            json.WriteStartObject();
            json.WriteString("input_sha256", digest);
            json.WriteStartArray("records");
            foreach (ref readonly var site in records.Sites.AsSpan()) {
                buffer.AsSpan().Fill(0xA5);
                int length = DispatchRecords.WriteText(extraction, site, buffer.AsSpan(0, records.BufferLength));
                Assert(buffer[length] == 0 && buffer.AsSpan(0, length).IndexOf((byte)0) < 0);
                Assert(buffer.AsSpan(length + 1).IndexOfAnyExcept((byte)0xA5) < 0);
                expectedLength += length;
                json.WriteStartArray();
                json.WriteBooleanValue(site.Data);
                json.WriteNumberValue(site.Address);
                json.WriteNumberValue(site.Key);
                json.WriteStringValue(buffer.AsSpan(0, length));
                json.WriteEndArray();
            }
            json.WriteEndArray();
            json.WriteEndObject();
            json.Flush();

            // The native runtime counts unused allocation contexts discarded by background GC
            Assert(GC.TryStartNoGCRegion(1024 * 1024));
            long allocated = GC.GetAllocatedBytesForCurrentThread();
            started = Stopwatch.GetTimestamp();
            long total = 0;
            const int trials = 10;
            for (int trial = 0; trial < trials; ++trial) {
                foreach (ref readonly var site in records.Sites.AsSpan())
                    total += DispatchRecords.WriteText(extraction, site, buffer);
            }
            double renderMs = Stopwatch.GetElapsedTime(started).TotalMilliseconds / trials;
            long bytes = GC.GetAllocatedBytesForCurrentThread() - allocated;
            GC.EndNoGCRegion();
            Assert(bytes == 0 && total == trials * expectedLength);

            var shapes = new Dictionary<ulong, nint>(extraction.Dispatch.Maps.Count);
            ulong expectedWidth = 0;
            foreach (ref readonly var map in CollectionsMarshal.AsSpan(extraction.Dispatch.Maps)) {
                nint type = DispatchTypes.Map(map, integer, instance, statics);
                CheckMap(type, map);
                expectedWidth += Inspect.BNGetTypeWidth(type);
                ulong key = map.StandardCount | ((ulong)map.DefaultCount << 16) | ((ulong)map.StaticCount << 32) | ((ulong)map.StaticDefaultCount << 48);
                shapes.TryAdd(key, 0);
                Core.BNFreeType(type);
            }
            int unique = shapes.Count;
            shapes.Clear();
            Assert(GC.TryStartNoGCRegion(1024 * 1024));
            for (int trial = 0; trial < 10; ++trial) {
                bool reuse = (trial & 1) != 0;
                ulong width = 0;
                allocated = GC.GetAllocatedBytesForCurrentThread();
                started = Stopwatch.GetTimestamp();
                foreach (ref readonly var map in CollectionsMarshal.AsSpan(extraction.Dispatch.Maps)) {
                    ulong key = map.StandardCount | ((ulong)map.DefaultCount << 16) | ((ulong)map.StaticCount << 32) | ((ulong)map.StaticDefaultCount << 48);
                    nint type = 0;
                    if (!reuse || !shapes.TryGetValue(key, out type)) {
                        type = DispatchTypes.Map(map, integer, instance, statics);
                        if (reuse)
                            shapes.Add(key, type);
                    }
                    width += Inspect.BNGetTypeWidth(type);
                    if (!reuse)
                        Core.BNFreeType(type);
                }
                if (reuse)
                    cached[trial / 2] = Stopwatch.GetElapsedTime(started).TotalMilliseconds;
                else
                    uncached[trial / 2] = Stopwatch.GetElapsedTime(started).TotalMilliseconds;
                Assert(width == expectedWidth && GC.GetAllocatedBytesForCurrentThread() == allocated);
                foreach (nint type in shapes.Values)
                    Core.BNFreeType(type);
                shapes.Clear();
            }
            GC.EndNoGCRegion();
            cached.Sort();
            uncached.Sort();
            Console.WriteLine($"Dispatch {digest[..12]}: {extraction.Dispatch.Maps.Count} native map layouts, {records.Sites.Length} tags, largest group {records.MaximumGroup}; prepare/sort {prepareMs:F3} ms, render {renderMs:F3} ms, {bytes} managed bytes per render.");
            Console.WriteLine($"Dispatch core construction: {unique} unique layouts; median uncached {uncached[2]:F3} ms, cached {cached[2]:F3} ms.");
        }
        Core.BNFreeType(statics);
        Core.BNFreeType(instance);
        Core.BNFreeType(integer);
    }

    private static void CheckEntry(nint type, bool isStatic) {
        Assert(Inspect.BNGetTypeClass(type) == 4 && Inspect.BNGetTypeWidth(type) == (isStatic ? 8U : 6U));
        nint structure = Inspect.BNGetTypeStructure(type);
        Assert(Inspect.BNIsStructurePacked(structure) != 0);
        nuint count = 0;
        StructureMember* members = Inspect.BNGetStructureMembers(structure, &count);
        string[] names = ["interface_index", "interface_slot", "implementation_slot", "context_source"];
        Assert(count == (isStatic ? 4U : 3U));
        for (int i = 0; i < (int)count; ++i) {
            Assert(Marshal.PtrToStringUTF8(members[i].Name) == names[i]);
            Assert(members[i].Offset == (uint)i * 2 && Inspect.BNGetTypeWidth(members[i].Type) == 2);
            Assert(members[i].Confidence == 255 && Inspect.BNGetTypeClass(members[i].Type) == 2);
        }
        Inspect.BNFreeStructureMemberList(members, count);
        Core.BNFreeStructure(structure);
    }

    private static void CheckMap(nint type, in DispatchMap map) {
        Assert(Inspect.BNGetTypeWidth(type) == (uint)(8 + 6 * (map.StandardCount + map.DefaultCount) + 8 * (map.StaticCount + map.StaticDefaultCount)));
        nint structure = Inspect.BNGetTypeStructure(type);
        Assert(Inspect.BNIsStructurePacked(structure) != 0);
        nuint count = 0;
        StructureMember* members = Inspect.BNGetStructureMembers(structure, &count);
        Span<int> counts = stackalloc int[4] { map.StandardCount, map.DefaultCount, map.StaticCount, map.StaticDefaultCount };
        string[] names = ["standard", "default", "static", "static_default"];
        int expected = 4;
        for (int i = 0; i < 4; ++i)
            expected += counts[i] != 0 ? 1 : 0;
        Assert(count == (uint)expected);
        uint offset = 8;
        for (int i = 0; i < (int)count; ++i) {
            ref readonly var member = ref members[i];
            string name = Marshal.PtrToStringUTF8(member.Name)!;
            if (member.Offset < 8) {
                Assert(name == names[member.Offset / 2] + "_count" && (member.Offset & 1) == 0);
                Assert(Inspect.BNGetTypeClass(member.Type) == 2 && Inspect.BNGetTypeWidth(member.Type) == 2);
            } else {
                int group = Array.IndexOf(names, name[..^8]);
                Assert(group >= 0 && name.EndsWith("_entries", StringComparison.Ordinal));
                Assert(member.Offset == offset && Inspect.BNGetTypeElementCount(member.Type) == (uint)counts[group]);
                Assert(Inspect.BNGetTypeClass(member.Type) == 7);
                var child = Inspect.BNGetChildType(member.Type);
                CheckEntry(child.Type, group >= 2);
                Core.BNFreeType(child.Type);
                offset += (uint)counts[group] * (group < 2 ? 6U : 8U);
            }
        }
        Inspect.BNFreeStructureMemberList(members, count);
        Core.BNFreeStructure(structure);
    }

    private static void Assert(bool condition) {
        if (!condition)
            throw new InvalidDataException("Native dispatch annotations differ from the metadata records.");
    }
}

internal static unsafe partial class Inspect {
    [LibraryImport("binaryninjacore")] internal static partial byte BNGetTypeClass(nint type);
    [LibraryImport("binaryninjacore")] internal static partial TypeConfidence BNGetChildType(nint type);
}
