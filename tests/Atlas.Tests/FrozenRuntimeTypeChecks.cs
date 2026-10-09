using System.Buffers.Binary;
using System.Text.RegularExpressions;
using Atlas;

internal static class FrozenRuntimeTypeChecks {
    internal static void Run(string imagePath, string mapPath) {
        var extraction = Read(File.ReadAllBytes(imagePath));
        var oracle = File.ReadLines(mapPath)
            .Select(line => Regex.Match(line, @"^\s+\d{4}:[0-9a-fA-F]+\s+\?\?_7\S+\s+([0-9a-fA-F]{16})\s+Probe.obj"))
            .Where(match => match.Success)
            .Select(match => Convert.ToUInt64(match.Groups[1].Value, 16)).ToHashSet();
        var recovered = extraction.Types.Types.Select(type => type.Address).ToHashSet();

        Assert(recovered.Except(oracle).Count() == 0,
            "Recovery introduced an EEType outside the independent linker oracle.");
        Assert(oracle.Except(recovered).Count() == 2,
            "Expected only the two code-only cast EETypes to remain absent.");
        Assert(extraction.Frozen.RuntimeTypes.Count > 20, "Missing compiler-emitted runtime type bindings.");

        foreach (var binding in extraction.Frozen.RuntimeTypes) {
            var type = extraction.Types.Types[binding.TypeIndex];
            Assert((type.Evidence & TypeEvidence.FrozenRuntimeType) != 0, "Missing evidence provenance.");

            var entry = extraction.Frozen.Objects[binding.ObjectIndex];
            Assert(BinaryPrimitives.ReadUInt64LittleEndian(extraction.Frozen.Data.Span[entry.Data.Start..])
                == type.Address, "Incorrect owner association.");
        }

        var publishedBindings = extraction.Frozen.RuntimeTypes.ToArray();
        var publishedTypes = extraction.Types.Types.ToArray();
        extraction.Frozen.ReadRuntimeTypes(extraction.Image, extraction.Header, extraction.Memory, extraction.Types);
        Assert(publishedBindings.SequenceEqual(extraction.Frozen.RuntimeTypes),
            "Repeated discovery duplicated or changed published bindings.");
        Assert(publishedTypes.SequenceEqual(extraction.Types.Types),
            "Repeated discovery changed parsed type identity.");

        try {
            extraction.Frozen.ReadRuntimeTypes(
                new PeImage((byte[])extraction.Image.FileData.Clone()),
                extraction.Header, extraction.Memory, extraction.Types);
            throw new Exception("Changing the source context was accepted.");
        } catch (InvalidOperationException) { }

        Assert(publishedBindings.SequenceEqual(extraction.Frozen.RuntimeTypes),
            "Failed discovery changed published bindings.");

        var tables = new MethodTables();

        foreach (var type in extraction.Types.Types)
            tables.Add(type.Address, TypeEvidence.TypeMap);

        tables.Read(extraction.Image, extraction.Header, extraction.Memory);
        var before = tables.Types.ToArray();
        var pointers = tables.Pointers.ToArray();

        tables.Read(extraction.Image, extraction.Header, extraction.Memory);
        Assert(pointers.SequenceEqual(tables.Pointers), "Repeat read duplicated pointer storage.");
        Assert(before.SequenceEqual(tables.Types), "Repeat read altered existing type IDs or ranges.");

        foreach (ulong missing in oracle.Except(recovered))
            tables.Add(missing, TypeEvidence.TypeMap);

        tables.Read(extraction.Image, extraction.Header, extraction.Memory);
        Assert(before.Select(WithoutEvidence)
            .SequenceEqual(tables.Types.Take(before.Length).Select(WithoutEvidence)),
            "Appended roots changed existing type IDs or ranges.");
        Assert(pointers.SequenceEqual(tables.Pointers.Take(pointers.Length)),
            "Appended roots changed existing pointer storage.");

        var together = new MethodTables();

        foreach (var type in tables.Types)
            together.Add(type.Address, type.Evidence);

        together.Read(extraction.Image, extraction.Header, extraction.Memory);

        for (int i = 0; i < tables.Types.Count; ++i) {
            var left = tables.Types[i];
            var right = together.Types[i];

            foreach (var pair in new[] {
                (left.Vtable, right.Vtable),
                (left.Interfaces, right.Interfaces),
                (left.Arguments, right.Arguments)
            })
                Assert(tables.Pointers.Skip(pair.Item1.Start).Take(pair.Item1.Count)
                    .SequenceEqual(together.Pointers.Skip(pair.Item2.Start).Take(pair.Item2.Count)),
                    "Batched pointer contents differ.");

            left.Vtable = left.Interfaces = left.Arguments = default;
            right.Vtable = right.Interfaces = right.Arguments = default;
            Assert(left.Equals(right), "Batched and single-pass parsing disagree.");
        }

        var alternativeImage = new PeImage((byte[])extraction.Image.FileData.Clone());

        foreach (int context in Enumerable.Range(0, 3)) {
            bool rebindRejected = false;

            try {
                tables.Read(context == 0 ? alternativeImage : extraction.Image,
                    context == 1 ? ReadyToRun.Read(alternativeImage) : extraction.Header,
                    context == 2 ? new RuntimeMemory(extraction.Image, extraction.Hydrated) : extraction.Memory);
            } catch (InvalidOperationException) {
                rebindRejected = true;
            }

            Assert(rebindRejected, $"Source context rebind {context} was accepted.");
        }

        foreach (int context in Enumerable.Range(0, 3)) {
            bool rejected = false;

            try {
                extraction.Frozen.ReadRuntimeTypes(
                    context == 0 ? alternativeImage : extraction.Image,
                    context == 1 ? ReadyToRun.Read(alternativeImage) : extraction.Header,
                    context == 2
                        ? new RuntimeMemory(PeFixture.Create(new byte[32], ".rdata", 0x40000040), default)
                        : extraction.Memory,
                    extraction.Types);
            } catch (InvalidOperationException) {
                rejected = true;
            }

            Assert(rejected, $"Frozen recovery source rebind {context} was accepted.");
            Assert(publishedBindings.SequenceEqual(extraction.Frozen.RuntimeTypes),
                "Rejected context rebind changed published bindings.");
        }

        tables.Read(extraction.Image, extraction.Header, extraction.Memory);

        var array = tables.Types.First(type => type.Kind == 2);
        bool lateGvmRejected = false;

        try {
            tables.Add(array.Address, TypeEvidence.GenericVirtualMethod);
        } catch (InvalidDataException) {
            lateGvmRejected = true;
        }

        Assert(lateGvmRejected, "Late GVM evidence bypassed owner validation.");

        var empty = new FrozenObjects(default, extraction.Memory, tables);
        empty.ReadRuntimeTypes(extraction.Image, extraction.Header, extraction.Memory, tables);
        Assert(empty.RuntimeTypes.Count == 0, "Absent frozen roots were invented.");

        var first = extraction.Frozen.RuntimeTypes[0];
        var firstObject = extraction.Frozen.Objects[first.ObjectIndex];
        ulong objectAddress = extraction.Frozen.Start + (uint)firstObject.Offset;
        ulong typeAddress = extraction.Types.Types[first.TypeIndex].Address;
        ulong cacheAddress = extraction.Types.Types[first.TypeIndex].WritableData;

        foreach (int fault in Enumerable.Range(0, 4)) {
            byte[] damaged = (byte[])extraction.Image.FileData.Clone();
            ulong location = fault == 2 ? cacheAddress : objectAddress + (fault == 1 ? 16UL : 8UL);
            ulong value = fault switch {
                0 => 0,
                1 => 1,
                2 => objectAddress + 32,
                _ => typeAddress + 1
            };
            BinaryPrimitives.WriteUInt64LittleEndian(
                damaged.AsSpan(extraction.Image.FileRange(location).Start), value);

            bool rejected = false;

            try {
                _ = Read(damaged);
            } catch (InvalidDataException) {
                rejected = true;
            }

            Assert(rejected, $"Malformed reciprocal binding {fault} was accepted.");
        }

        byte[] withoutCaches = (byte[])extraction.Image.FileData.Clone();

        foreach (var binding in extraction.Frozen.RuntimeTypes) {
            ulong cache = extraction.Types.Types[binding.TypeIndex].WritableData;
            withoutCaches.AsSpan(extraction.Image.FileRange(cache).Start, 8).Clear();
        }

        var unanchored = Read(withoutCaches);
        Assert(unanchored.Frozen.RuntimeTypes.Count == 0,
            "Missing reciprocal anchors invented runtime type identity.");
        Assert(unanchored.Types.Types.Count == extraction.Types.Types.Count - 5,
            "Unexpected roots without reciprocal anchors.");

        Console.WriteLine($"Frozen runtime types: {extraction.Frozen.RuntimeTypes.Count} bindings, {recovered.Count}/{oracle.Count} oracle types, zero false positives; append-only and malformed checks passed.");
    }

    private static Extraction Read(byte[] bytes) {
        var image = new PeImage(bytes);
        var header = ReadyToRun.Read(image);
        var section = header.Find(RtrSectionId.EmbeddedMetadata);
        var metadata = new Metadata(
            image.FileMemory(section.Start, checked((int)section.Length)), header.MetadataHandleBits);
        metadata.ReadDefinitions();

        var fixups = RuntimeTables.Fixups(image, header.Find(RtrSectionId.CommonFixupsTable));
        var maps = new ReflectionMaps();
        maps.Read(image, header, metadata, fixups);

        return new Extraction(image, header, metadata, maps, fixups);
    }

    private static MethodTable WithoutEvidence(MethodTable type) {
        type.Evidence = TypeEvidence.None;
        return type;
    }

    private static void Assert(bool condition, string message) {
        if (!condition)
            throw new Exception(message);
    }
}
