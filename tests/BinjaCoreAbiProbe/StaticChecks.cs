using System.Buffers.Binary;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text.Json;
using Atlas;
using Atlas.Binja;

internal static unsafe class StaticChecks {
    internal static void Run(ReadOnlySpan<string> binaries) {
        byte empty = 0;
        BoolConfidence signed = new() { Value = 1, Confidence = 255 }, unsigned = new() { Confidence = 255 }, qualifier = default;
        nint i32 = Core.BNCreateIntegerType(4, &signed, &empty);
        nint u32 = Core.BNCreateIntegerType(4, &unsigned, &empty);
        nint i64 = Core.BNCreateIntegerType(8, &signed, &empty);
        nint nothing = Core.BNCreateVoidType();
        var target = new TypeConfidence(nothing);
        nint pointer = Core.BNCreatePointerTypeOfWidth(8, &target, &qualifier, &qualifier, 0);
        nint header = StaticTypes.Header(u32, pointer);
        nint retainedHeader = Core.BNNewTypeReference(header);
        Core.BNFreeType(header);
        header = retainedHeader;
        nint cell = StaticTypes.Cell(i32, false), preinit = StaticTypes.Cell(i32, true);
        nint threadIndex = StaticTypes.ThreadIndex(pointer, i64);
        Check(header, 16, [("flags", 0, 4), ("base_size", 4, 4), ("related_type", 8, 8)]);
        Check(cell, 8, [("tagged_descriptor_rel32", 0, 4)]);
        Check(preinit, 8, [("tagged_descriptor_rel32", 0, 4), ("preinit_rel32", 4, 4)]);
        Check(threadIndex, 16, [("type_manager", 0, 8), ("index", 8, 8)]);
        var headerConfidence = new TypeConfidence(header);
        nint descriptor = Core.BNCreatePointerTypeOfWidth(8, &headerConfidence, &qualifier, &qualifier, 0);

        Span<double> cachedTimes = stackalloc double[5], uncachedTimes = stackalloc double[5];
        foreach (string binary in binaries) {
            var image = new PeImage(File.ReadAllBytes(binary));
            var rtr = ReadyToRun.Read(image);
            var section = rtr.Find(313);
            var metadata = new Metadata(section.Length == 0 ? default : image.FileMemory(section.Start, checked((int)section.Length)),
                rtr.MetadataHandleBits, rtr.Major < 10);
            metadata.ReadDefinitions();
            var fixups = RuntimeTables.Fixups(image, rtr.Find(308));
            var maps = new ReflectionMaps();
            maps.Read(image, rtr, metadata, fixups, MapFormat.Auto);
            var extraction = new Extraction(image, rtr, metadata, maps, fixups);
            var statics = extraction.Statics;
            string digest = Convert.ToHexStringLower(SHA256.HashData(image.FileData));
            var counts = new[] { statics.Allocations.Count, statics.GcCells.Count, statics.ThreadIndices.Count,
                statics.Constructors.Count, statics.Generics.Count, statics.Fields.Count };
            int tagCount = counts.Sum();
            byte[] text = new byte[StaticText.BufferLength(extraction) + 8];
            long expectedLength = 0;
            var addresses = new HashSet<ulong>(tagCount);
            using var stream = File.Create(Path.Combine(AppContext.BaseDirectory, $"statics-{digest[..12]}.json"));
            using var json = new Utf8JsonWriter(stream);
            json.WriteStartObject();
            json.WriteString("input_sha256", digest);
            json.WriteStartArray("tags");
            for (int kind = 0; kind < counts.Length; ++kind) {
                for (int i = 0; i < counts[kind]; ++i) {
                    ulong address = (StaticRecord)kind switch {
                        StaticRecord.Allocation => statics.Allocations[i].Address,
                        StaticRecord.Cell => statics.GcCells[i].Cell,
                        StaticRecord.ThreadIndex => statics.ThreadIndices[i].Address,
                        StaticRecord.Constructor => rtr.Find(310).Start + (uint)statics.Constructors[i].Vertex,
                        StaticRecord.Generic => rtr.Find(334).Start + (uint)statics.Generics[i].Vertex,
                        _ => rtr.Find(309).Start + (uint)maps.Fields[statics.Fields[i].FieldMapIndex].Vertex
                    };
                    Assert(addresses.Add(address));
                    text.AsSpan().Fill(0xA5);
                    int length = StaticText.Write(extraction, (StaticRecord)kind, i, text.AsSpan(0, text.Length - 8));
                    Assert(text[length] == 0 && text.AsSpan(0, length).IndexOf((byte)0) < 0);
                    Assert(text.AsSpan(length + 1).IndexOfAnyExcept((byte)0xA5) < 0);
                    expectedLength += length;
                    json.WriteStartArray();
                    json.WriteNumberValue(address);
                    json.WriteStringValue(text.AsSpan(0, length));
                    json.WriteEndArray();
                }
            }
            json.WriteEndArray();
            json.WriteEndObject();
            json.Flush();

            int references = 0;
            foreach (ref readonly var allocation in CollectionsMarshal.AsSpan(statics.Allocations)) {
                for (int payload = 0; payload < 2; ++payload) {
                    var members = new List<(string Name, ulong Offset, ulong Width)>();
                    if (payload == 0)
                        members.Add(("__allocation_descriptor", 0, 8));
                    for (int j = allocation.Runs.Start; j < allocation.Runs.End; ++j) {
                        var run = statics.Runs[j];
                        for (uint k = 0; k < run.Count; ++k) {
                            uint offset = run.Offset + k * 8 - (payload == 0 ? 0U : 8U);
                            members.Add(($"_ref_{offset:X2}", offset, 8));
                        }
                    }
                    members.Sort(static (a, b) => a.Offset.CompareTo(b.Offset));
                    nint type = StaticTypes.Storage(allocation, CollectionsMarshal.AsSpan(statics.Runs), descriptor, pointer, payload != 0);
                    Check(type, allocation.BaseSize - (payload == 0 ? 8U : 16U), CollectionsMarshal.AsSpan(members));
                    Core.BNFreeType(type);
                }
                if (allocation.Runs.Count != 0) {
                    nint gc = StaticTypes.GcDesc(allocation.Runs.Count, i64);
                    ulong seriesWidth = (uint)allocation.Runs.Count * 16UL;
                    Check(gc, seriesWidth + 8, [("series", 0, seriesWidth), ("count", seriesWidth, 8)]);
                    Core.BNFreeType(gc);
                }
            }
            foreach (ref readonly var entry in CollectionsMarshal.AsSpan(statics.GcCells)) {
                if (entry.PreinitData == 0)
                    continue;
                var allocation = statics.Allocations[statics.AllocationIndex[entry.Descriptor]];
                var bytes = extraction.Memory.Read(entry.PreinitData, checked((int)(allocation.BaseSize - 16)));
                for (int j = allocation.Runs.Start; j < allocation.Runs.End; ++j) {
                    var run = statics.Runs[j];
                    for (uint k = 0; k < run.Count; ++k) {
                        ulong value = BinaryPrimitives.ReadUInt64LittleEndian(bytes[(int)(run.Offset - 8 + k * 8)..]);
                        Assert(value == 0 || extraction.Frozen.Index.ContainsKey(value));
                        references += value == 0 ? 0 : 1;
                    }
                }
            }

            Assert(GC.TryStartNoGCRegion(1024 * 1024));
            long allocated = GC.GetAllocatedBytesForCurrentThread();
            long started = Stopwatch.GetTimestamp(), total = 0;
            for (int trial = 0; trial < 10; ++trial) {
                for (int kind = 0; kind < counts.Length; ++kind) {
                    for (int i = 0; i < counts[kind]; ++i)
                        total += StaticText.Write(extraction, (StaticRecord)kind, i, text);
                }
            }
            double elapsed = Stopwatch.GetElapsedTime(started).TotalMilliseconds / 10;
            long allocatedBytes = GC.GetAllocatedBytesForCurrentThread() - allocated;
            GC.EndNoGCRegion();
            Assert(allocatedBytes == 0 && total == expectedLength * 10);
            Console.WriteLine($"Statics {digest[..12]}: {statics.Allocations.Count} allocation layouts, {tagCount} tags, {references} preinitialized frozen references; render {elapsed:F3} ms, {allocatedBytes} managed bytes.");

            var payloads = new List<int>(statics.GcCells.Count);
            var preinitAddresses = new HashSet<ulong>(statics.GcCells.Count);
            ulong expectedWidth = 0;
            foreach (ref readonly var entry in CollectionsMarshal.AsSpan(statics.GcCells)) {
                if (entry.PreinitData != 0 && preinitAddresses.Add(entry.PreinitData)) {
                    int allocation = statics.AllocationIndex[entry.Descriptor];
                    payloads.Add(allocation);
                    expectedWidth += statics.Allocations[allocation].BaseSize - 16;
                }
            }
            nint[] shapes = new nint[statics.Allocations.Count];
            Assert(GC.TryStartNoGCRegion(1024 * 1024));
            for (int trial = 0; trial < 10; ++trial) {
                bool reuse = (trial & 1) != 0;
                ulong width = 0;
                allocated = GC.GetAllocatedBytesForCurrentThread();
                started = Stopwatch.GetTimestamp();
                foreach (int index in CollectionsMarshal.AsSpan(payloads)) {
                    nint type = shapes[index];
                    if (type == 0) {
                        type = StaticTypes.Storage(statics.Allocations[index], CollectionsMarshal.AsSpan(statics.Runs), descriptor, pointer, true);
                        if (reuse)
                            shapes[index] = type;
                    }
                    width += Core.BNGetTypeWidth(type);
                    if (!reuse)
                        Core.BNFreeType(type);
                }
                if (reuse)
                    cachedTimes[trial / 2] = Stopwatch.GetElapsedTime(started).TotalMilliseconds;
                else
                    uncachedTimes[trial / 2] = Stopwatch.GetElapsedTime(started).TotalMilliseconds;
                Assert(width == expectedWidth && GC.GetAllocatedBytesForCurrentThread() == allocated);
                foreach (nint type in shapes) {
                    if (type != 0)
                        Core.BNFreeType(type);
                }
                shapes.AsSpan().Clear();
            }
            GC.EndNoGCRegion();
            cachedTimes.Sort();
            uncachedTimes.Sort();
            Console.WriteLine($"Static payload construction: {payloads.Count} payloads; median uncached {uncachedTimes[2]:F3} ms, cached {cachedTimes[2]:F3} ms.");
        }
        Core.BNFreeType(descriptor);
        Core.BNFreeType(header);
        Core.BNFreeType(cell);
        Core.BNFreeType(preinit);
        Core.BNFreeType(threadIndex);
        Core.BNFreeType(pointer);
        Core.BNFreeType(nothing);
        Core.BNFreeType(i64);
        Core.BNFreeType(u32);
        Core.BNFreeType(i32);
    }

    private static void Check(nint type, ulong width, ReadOnlySpan<(string Name, ulong Offset, ulong Width)> expected) {
        Assert(Core.BNGetTypeWidth(type) == width);
        nint structure = Inspect.BNGetTypeStructure(type);
        Assert(Inspect.BNIsStructurePacked(structure) != 0);
        nuint count = 0;
        StructureMember* members = Inspect.BNGetStructureMembers(structure, &count);
        Assert(count == (uint)expected.Length);
        for (int i = 0; i < expected.Length; ++i) {
            Assert(Marshal.PtrToStringUTF8(members[i].Name) == expected[i].Name);
            Assert(members[i].Offset == expected[i].Offset && Core.BNGetTypeWidth(members[i].Type) == expected[i].Width);
            string name = expected[i].Name;
            byte kind = name.StartsWith("_ref_", StringComparison.Ordinal)
                || name is "__allocation_descriptor" or "related_type" or "type_manager" ? (byte)6
                : name == "series" ? (byte)7 : (byte)2;
            Assert(Inspect.BNGetTypeClass(members[i].Type) == kind);
        }
        Inspect.BNFreeStructureMemberList(members, count);
        Core.BNFreeStructure(structure);
    }

    private static void Assert(bool condition) {
        if (!condition)
            throw new InvalidDataException("Static annotations differ from the runtime storage records.");
    }
}
