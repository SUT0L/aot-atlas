using System.Buffers.Binary;
using System.Globalization;
using System.Text;
using Atlas;

internal static class MarshallingProducerChecks {
    private readonly record struct Layout(
        string Name, uint Size, NativeSizeSource SizeSource, string[] Names, uint[] Offsets);

    // These extents follow the declarations in MarshallingProbe: byte packing,
    // four-byte native BOOLs, UTF-16 inline text, and eight-byte native pointers.
    private static readonly Layout[] Layouts = [
        new("Blittable", 9, NativeSizeSource.MethodTable, ["Tag", "Value"], [0, 1]),
        new("NativeBool", 7, NativeSizeSource.MarshallingMap, ["Tag", "Enabled", "Code"], [0, 1, 5]),
        new("Inline", 20, NativeSizeSource.MarshallingMap, ["Code", "Text", "Samples"], [0, 2, 14]),
        new("Owned", 16, NativeSizeSource.MarshallingMap, ["Text", "Number"], [0, 8]),
        new("LayoutClass", 7, NativeSizeSource.MarshallingMap, ["Tag", "Enabled", "Code"], [0, 1, 5])
    ];

    internal static void Run(string binary, string linkerMap) {
        var image = PeImage.ReadFile(binary);
        var header = ReadyToRun.Read(image);
        var metadata = Metadata.FromImage(image, header);
        metadata.ReadDefinitions();
        var fixups = RuntimeTables.ReadFixups(image, header.Find(RtrSectionId.CommonFixupsTable)).ToArray();
        var maps = ReflectionMaps.Decode(image, header, metadata, fixups);
        var symbols = ReadSymbols(linkerMap);
        var selected = new Extraction(image, header, metadata, maps, fixups, ExtractionStage.RuntimeTypes);
        var full = new Extraction(image, header, metadata, maps, fixups);

        Check(selected.Stages == ExtractionStage.RuntimeTypes, "The narrow extraction added stages.");
        CheckConcurrentOwners(selected);
        CheckLayouts(selected, symbols);
        CheckLayouts(full, symbols);
        CheckOwners(selected, full);
        CheckFaults(image, header, metadata, maps, fixups, selected, symbols);

        Console.WriteLine($"Marshalling producer: {binary}; five layouts, thirteen fields, invalid layout, four conversion/cleanup triplets, delegate open/closed/create, narrow/full owners, raw records, hash/record faults and repaired retries passed.");
    }

    private static void CheckLayouts(Extraction extraction, Dictionary<string, ulong> symbols) {
        var marshalling = extraction.Marshalling;
        Check(marshalling.StructEntries.Length == 6 && marshalling.FieldEntries.Length == 13
            && marshalling.DelegateEntries.Length == 1, "The producer fixture lost positive marshalling records.");

        foreach (var expected in Layouts) {
            ulong address = TypeAddress(symbols, expected.Name, expected.Name != "LayoutClass");
            int position = StructPosition(extraction, address);
            var entry = marshalling.StructEntries[position];
            Check(extraction.NativeStructTypeAt(position).Address == address,
                $"{expected.Name}: public runtime reference differs from the linker type symbol.");
            Check(extraction.Names.Values[entry.TypeIndex] == $"MarshallingFixture.{expected.Name}",
                $"{expected.Name}: retained type name differs from the source declaration.");
            Check(entry.Size == expected.Size && entry.SizeSource == expected.SizeSource
                && entry.HasLayoutSize && !entry.InvalidLayout && entry.Fields.Count == expected.Names.Length,
                $"{expected.Name}: native size or layout provenance differs from the source declaration.");

            bool blittable = expected.Name == "Blittable";
            uint expectedHeader = (uint)expected.Names.Length << 2 | (blittable ? 0U : 1U);
            Check(entry.Header == expectedHeader, $"{expected.Name}: native header differs from the compiler grammar.");

            int cursor = entry.Vertex;
            var bytes = marshalling.StructBytes;
            Check(extraction.Fixups[checked((int)ReadUnsigned(bytes, ref cursor))] == address
                && ReadUnsigned(bytes, ref cursor) == expectedHeader,
                $"{expected.Name}: raw record does not identify the declared type and header.");

            if (blittable) {
                Check(entry.ToNative == 0 && entry.ToManaged == 0 && entry.Cleanup == 0,
                    "A blittable layout invented marshalling stubs.");
            } else {
                Check(ReadUnsigned(bytes, ref cursor) == expected.Size,
                    $"{expected.Name}: raw native size differs from the declaration.");
                CheckStub(extraction, symbols, entry.ToNative, "ManagedToNative", expected.Name,
                    extraction.Fixups[checked((int)ReadUnsigned(bytes, ref cursor))]);
                CheckStub(extraction, symbols, entry.ToManaged, "NativeToManaged", expected.Name,
                    extraction.Fixups[checked((int)ReadUnsigned(bytes, ref cursor))]);
                CheckStub(extraction, symbols, entry.Cleanup, "Cleanup", expected.Name,
                    extraction.Fixups[checked((int)ReadUnsigned(bytes, ref cursor))]);
            }

            for (int i = 0; i < expected.Names.Length; ++i) {
                int length = checked((int)ReadUnsigned(bytes, ref cursor));
                string rawName = Encoding.UTF8.GetString(bytes.Slice(cursor, length));
                cursor += length;
                uint rawOffset = ReadUnsigned(bytes, ref cursor);
                var field = marshalling.FieldEntries[entry.Fields.Start + i];
                string parsedName = Encoding.UTF8.GetString(bytes.Slice(field.Name.Start, field.Name.Count));
                Check(rawName == expected.Names[i] && rawOffset == expected.Offsets[i]
                    && parsedName == rawName && field.Offset == rawOffset,
                    $"{expected.Name}.{expected.Names[i]}: raw or parsed offset differs from the declared native layout.");
            }

            Check(cursor == entry.Vertex + entry.Length,
                $"{expected.Name}: record extent differs from the compiler grammar.");
            CheckHash(extraction, entry.TypeIndex, entry.Hash,
                extraction.Header.Find(RtrSectionId.StructMarshallingStubMap));
        }

        int invalidPosition = StructPosition(extraction, TypeAddress(symbols, "InvalidLayout", true));
        var invalid = marshalling.StructEntries[invalidPosition];
        int invalidCursor = invalid.Vertex;
        Check(extraction.Fixups[checked((int)ReadUnsigned(marshalling.StructBytes, ref invalidCursor))]
                == extraction.NativeStructTypeAt(invalidPosition).Address
            && ReadUnsigned(marshalling.StructBytes, ref invalidCursor) == 2
            && invalidCursor == invalid.Vertex + invalid.Length,
            "The invalid source layout differs from its raw compiler record.");
        Check(invalid.InvalidLayout && invalid.Size == 0 && invalid.SizeSource == NativeSizeSource.Unknown
            && !invalid.HasLayoutSize && invalid.Fields.Count == 0 && invalid.ToNative == 0
            && invalid.ToManaged == 0 && invalid.Cleanup == 0,
            "An invalid layout published native fields, size, or callable stubs.");

        var callback = marshalling.DelegateEntries[0];
        ulong callbackAddress = TypeAddress(symbols, "Callback", false);
        Check(extraction.NativeDelegateTypeAt(0).Address == callbackAddress,
            "The callback runtime reference differs from its linker type symbol.");
        var delegateSection = extraction.Header.Find(RtrSectionId.DelegateMarshallingStubMap);
        var delegateBytes = extraction.Image.FileSpan(delegateSection.Start, checked((int)delegateSection.Length));
        int delegateCursor = callback.Vertex;
        Check(extraction.Fixups[checked((int)ReadUnsigned(delegateBytes, ref delegateCursor))] == callbackAddress,
            "The raw delegate record differs from the callback declaration.");
        CheckStub(extraction, symbols, callback.Open, "ReverseOpenStaticDelegateStub", "Callback",
            extraction.Fixups[checked((int)ReadUnsigned(delegateBytes, ref delegateCursor))]);
        CheckStub(extraction, symbols, callback.Closed, "ReverseDelegateStub", "Callback",
            extraction.Fixups[checked((int)ReadUnsigned(delegateBytes, ref delegateCursor))]);
        CheckStub(extraction, symbols, callback.Create, "ForwardDelegateCreationStub", "Callback",
            extraction.Fixups[checked((int)ReadUnsigned(delegateBytes, ref delegateCursor))]);
        Check(delegateCursor == callback.Vertex + callback.Length,
            "The callback record extent differs from the compiler grammar.");
        CheckHash(extraction, callback.TypeIndex, callback.Hash, delegateSection);
    }

    private static void CheckOwners(Extraction selected, Extraction full) {
        foreach (var extraction in new[] { selected, full }) {
            var foreign = ReferenceEquals(extraction, full) ? selected : full;

            for (int i = 0; i < extraction.Marshalling.StructEntries.Length; ++i) {
                var own = extraction.NativeStructTypeAt(i);
                Check(own.IsResolved && own.Equals(extraction.NativeStructTypeAt(i)),
                    "Repeated struct references have different owners.");
                Check(own.Address == foreign.NativeStructTypeAt(i).Address
                    && !own.Equals(foreign.NativeStructTypeAt(i)),
                    "Narrow and full struct references lost their separate owners or address agreement.");

                if (ReferenceEquals(extraction, full)) {
                    var binding = full.Bindings;
                    var signature = TypeSignature(extraction, own.Address);
                    Check(binding.RuntimeType(own.Address).Equals(own)
                        && binding.Resolve(signature, own).Address == own.Address
                        && binding.Resolve(signature, methodArguments: [own]).Address == own.Address,
                        "A full extraction binding rejected its own struct reference.");
                    RejectOwner(() => binding.Resolve(signature, foreign.NativeStructTypeAt(i)));
                    RejectOwner(() => binding.Resolve(signature, methodArguments: [foreign.NativeStructTypeAt(i)]));
                }
            }

            var callback = extraction.NativeDelegateTypeAt(0);
            Check(callback.IsResolved && callback.Equals(extraction.NativeDelegateTypeAt(0))
                && callback.Address == foreign.NativeDelegateTypeAt(0).Address
                && !callback.Equals(foreign.NativeDelegateTypeAt(0)),
                "Delegate references lost stable ownership or narrow/full address agreement.");

            if (ReferenceEquals(extraction, full)) {
                var binding = full.Bindings;
                var signature = TypeSignature(full, callback.Address);
                Check(binding.RuntimeType(callback.Address).Equals(callback)
                    && binding.Resolve(signature, callback).Address == callback.Address,
                    "A full extraction binding rejected its own callback reference.");
                RejectOwner(() => binding.Resolve(signature, foreign.NativeDelegateTypeAt(0)));
                RejectOwner(() => binding.Resolve(signature, methodArguments: [foreign.NativeDelegateTypeAt(0)]));
            }

            RejectOwner(() => extraction.NativeStructTypeAt(-1));
            RejectOwner(() => extraction.NativeStructTypeAt(6));
            RejectOwner(() => extraction.NativeDelegateTypeAt(-1));
            RejectOwner(() => extraction.NativeDelegateTypeAt(1));
        }
    }

    private static void CheckConcurrentOwners(Extraction extraction) {
        using var start = new ManualResetEventSlim();
        using var ready = new CountdownEvent(4);
        var references = new RuntimeTypeReference[4];
        var readers = new Thread[references.Length];

        for (int i = 0; i < readers.Length; ++i) {
            int position = i;
            bool isStruct = (i & 1) == 0;
            readers[i] = new Thread(() => {
                ready.Signal();
                start.Wait();
                references[position] = isStruct ? extraction.NativeStructTypeAt(0) : extraction.NativeDelegateTypeAt(0);
            });
            readers[i].Start();
        }

        ready.Wait();
        start.Set();

        foreach (var reader in readers)
            reader.Join();

        for (int i = 0; i < readers.Length; ++i) {
            var expected = (i & 1) == 0 ? extraction.NativeStructTypeAt(0) : extraction.NativeDelegateTypeAt(0);
            Check(references[i].IsResolved && references[i].Equals(expected),
                "Concurrent first marshalling readers published different runtime owners.");
        }
    }

    private static void CheckFaults(
        PeImage original, ReadyToRun header, Metadata metadata, ReflectionMaps maps,
        ulong[] fixups, Extraction good, Dictionary<string, ulong> symbols) {
        var structSection = header.Find(RtrSectionId.StructMarshallingStubMap);
        var delegateSection = header.Find(RtrSectionId.DelegateMarshallingStubMap);
        var firstStruct = good.Marshalling.StructEntries[0];
        var firstDelegate = good.Marshalling.DelegateEntries[0];
        var graph = metadata.PublishedSignatures;
        var definitions = metadata.DefinitionHandles.ToArray();
        var typeMaps = maps.TypeEntries.ToArray();

        foreach (var fault in new[] {
            (Section: structSection, Offset: firstStruct.Vertex, Hash: false),
            (Section: delegateSection, Offset: firstDelegate.Vertex, Hash: false),
            (Section: structSection, Offset: HashPosition(original, structSection), Hash: true),
            (Section: delegateSection, Offset: HashPosition(original, delegateSection), Hash: true)
        }) {
            byte[] data = original.Bytes.ToArray();
            var image = new PeImage(data, takeOwnership: true);
            int offset = image.FileRange(fault.Section.Start).Start + fault.Offset;
            byte saved = data[offset];
            data[offset] = fault.Hash ? (byte)(saved == 0 ? 1 : saved - 1) : byte.MaxValue;

            for (int replay = 0; replay < 3; ++replay) {
                try {
                    _ = new Extraction(image, header, metadata, maps, fixups, ExtractionStage.RuntimeTypes);
                    throw new Exception("Malformed compiler marshalling record was accepted.");
                } catch (InvalidDataException error) {
                    Check(error.Message.Contains(fault.Hash ? "marshalling hash" : "NativeFormat integer", StringComparison.Ordinal),
                        "The corrupt compiler record failed outside its expected validation boundary.");
                }

                Check(ReferenceEquals(graph, metadata.PublishedSignatures)
                    && metadata.DefinitionHandles.SequenceEqual(definitions) && maps.TypeEntries.SequenceEqual(typeMaps),
                    "A failed extraction changed its accepted metadata or map input.");
            }

            data[offset] = saved;
            var repaired = new Extraction(image, header, metadata, maps, fixups, ExtractionStage.RuntimeTypes);
            CheckLayouts(repaired, symbols);
        }
    }

    private static int HashPosition(PeImage image, RtrSection section) {
        var bytes = image.FileSpan(section.Start, checked((int)section.Length));
        int count = 1 << (bytes[0] >> 2);
        int width = 1 << (bytes[0] & 3);

        for (int i = 0; i < count; ++i) {
            int start = Boundary(bytes, 1 + i * width, width);
            int end = Boundary(bytes, 1 + (i + 1) * width, width);
            if (start == end)
                continue;

            // Decreasing the first hash preserves bucket ordering. When all
            // hashes are zero, increasing the last hash preserves it instead.
            if (bytes[start] != 0)
                return start;

            int cursor = start;
            int last = start;
            while (cursor < end) {
                last = cursor++;
                ReadUnsigned(bytes, ref cursor);
            }

            if (bytes[last] == 0)
                return last;
        }

        throw new Exception("The compiler fixture has no mutable marshalling hash that preserves bucket ordering.");
    }

    private static int Boundary(ReadOnlySpan<byte> bytes, int offset, int width) {
        uint value = width switch {
            1 => bytes[offset],
            2 => BinaryPrimitives.ReadUInt16LittleEndian(bytes[offset..]),
            _ => BinaryPrimitives.ReadUInt32LittleEndian(bytes[offset..])
        };
        return checked((int)value + 1);
    }

    private static void CheckHash(Extraction extraction, int typeIndex, uint hash, RtrSection section) {
        byte tableHeader = extraction.Image.FileSpan(section.Start, 1)[0];
        uint mask = ((1U << (tableHeader >> 2)) - 1) << 8 | 255;
        ulong address = extraction.Types.Types[typeIndex].Address;
        uint rawTypeHash = BinaryPrimitives.ReadUInt32LittleEndian(extraction.Memory.Read(address + 20, 4));
        Check(hash == (rawTypeHash & mask), "A marshalling hash differs from the runtime type hash and table mask.");
    }

    private static void CheckStub(
        Extraction extraction, Dictionary<string, ulong> symbols, ulong address,
        string operation, string name, ulong rawAddress) {
        var matches = symbols.Where(symbol => symbol.Key.StartsWith("Internal_CompilerGenerated__Module___<", StringComparison.Ordinal)
            && symbol.Key.Contains($"<{operation}>", StringComparison.Ordinal)
            && symbol.Key.EndsWith($"_MarshallingFixture_{name}", StringComparison.Ordinal)).ToArray();
        Check(matches.Length == 1 && matches[0].Value == address && rawAddress == address
            && extraction.Image.IsExecutable(address),
            $"{name}: {operation} differs from the compiler/linker stub symbol or raw fixup.");
    }

    private static ulong TypeAddress(Dictionary<string, ulong> symbols, string name, bool valueType) {
        string prefix = valueType ? "??_7Boxed_" : "??_7";
        return symbols.Single(symbol => symbol.Key.StartsWith(prefix, StringComparison.Ordinal)
            && !symbol.Key.Contains('<')
            && symbol.Key.EndsWith($"_MarshallingFixture_{name}@@6B@", StringComparison.Ordinal)).Value;
    }

    private static int StructPosition(Extraction extraction, ulong address) {
        for (int i = 0; i < extraction.Marshalling.StructEntries.Length; ++i)
            if (extraction.NativeStructTypeAt(i).Address == address)
                return i;

        throw new Exception($"Missing compiler-produced struct at 0x{address:X}.");
    }

    private static SignatureType TypeSignature(Extraction extraction, ulong address) {
        for (int i = 0; i < extraction.Maps.TypeEntries.Length; ++i)
            if (extraction.Maps.TypeEntries[i].MethodTable == address)
                return extraction.Maps.TypeSignatureAt(i);

        throw new Exception($"Missing source type signature at 0x{address:X}.");
    }

    private static Dictionary<string, ulong> ReadSymbols(string path) {
        var symbols = new Dictionary<string, ulong>(StringComparer.Ordinal);
        foreach (string line in File.ReadLines(path)) {
            string[] columns = line.Split((char[]?)null, StringSplitOptions.RemoveEmptyEntries);
            if (columns.Length >= 3 && columns[0].Contains(':')
                && ulong.TryParse(columns[2], NumberStyles.HexNumber, CultureInfo.InvariantCulture, out ulong address))
                symbols.TryAdd(columns[1], address);
        }
        return symbols;
    }

    // Independent decoder for the compiler's compressed unsigned constants.
    private static uint ReadUnsigned(ReadOnlySpan<byte> bytes, ref int cursor) {
        uint first = bytes[cursor++];
        int trailing = 0;
        while ((first & (1U << trailing)) != 0)
            ++trailing;
        Check(trailing <= 4, "Invalid independent oracle integer.");
        if (trailing == 4) {
            uint value = BinaryPrimitives.ReadUInt32LittleEndian(bytes[cursor..]);
            cursor += 4;
            return value;
        }

        uint result = first >> (trailing + 1);
        for (int i = 0; i < trailing; ++i)
            result |= (uint)bytes[cursor++] << (7 - trailing + 8 * i);
        return result;
    }

    private static void RejectOwner(Action action) {
        try {
            action();
        } catch (ArgumentException) {
            return;
        }
        throw new Exception("A foreign marshalling reference or invalid position was accepted.");
    }

    private static void Check(bool condition, string message) {
        if (!condition)
            throw new Exception(message);
    }
}
