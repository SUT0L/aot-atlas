using System.Buffers.Binary;
using System.Text.RegularExpressions;
using Atlas;

internal static class FatFunctionPointerChecks {
    internal static void Run(
        string imagePath, string mapPath, int? expectedPointers = null, int? expectedDictionaries = null
    ) {
        var image = new PeImage(File.ReadAllBytes(imagePath));
        var header = ReadyToRun.Read(image);
        var memory = new RuntimeMemory(image, Hydration.Read(image, header));
        var analysis = new UnwindAnalysis(image, header, memory);
        var unwind = analysis.RequireUnwind();
        var map = new MethodGcMap(image, header, unwind, analysis.RequireManaged());

        var section = header.Find(RtrSectionId.EmbeddedMetadata);
        var metadata = new Metadata(image.FileMemory(section.Start, (int)section.Length),
            header.MetadataHandleBits, header.Format.LegacyMetadataConstants);
        metadata.ReadDefinitions();
        var traces = new TraceMaps(image, header, metadata,
            RuntimeTables.Fixups(image, header.Find(RtrSectionId.CommonFixupsTable)));
        var consumers = ManagedFunctionPointerConsumers.Read(metadata, traces, metadata.SignatureBuilder.Publish());
        var result = new FatFunctionPointers(image, header, memory, unwind, map, consumers);

        var symbols = File.ReadLines(mapPath).Select(line => Regex.Match(line,
            @"^\s+\d{4}:[0-9a-fA-F]+\s+(\S+)\s+([0-9a-fA-F]{16})\s+Probe.obj"))
            .Where(match => match.Success)
            .Select(match => (Name: match.Groups[1].Value, Address: Convert.ToUInt64(match.Groups[2].Value, 16)))
            .ToArray();
        var oracle = symbols.Where(symbol => symbol.Name.StartsWith("__fat", StringComparison.Ordinal)
            && symbol.Name.Contains("pointer_", StringComparison.Ordinal))
            .Select(symbol => symbol.Address).ToHashSet();
        var typeAddresses = symbols.Where(symbol => symbol.Name.StartsWith("??_7", StringComparison.Ordinal))
            .Select(symbol => symbol.Address).ToHashSet();

        Assert(result.Values.Count > 0 && result.Values.All(pointer => oracle.Contains(pointer.Descriptor)),
            "Unanchored descriptor entered the result.");
        Assert(result.Values.Select(pointer => pointer.Pointer).Distinct().Count() == result.Values.Count,
            "Duplicate descriptor identity.");

        foreach (var pointer in result.Values) {
            var bytes = memory.Read(pointer.Descriptor, 16);
            Assert(pointer.Pointer == pointer.Descriptor + 2
                && pointer.Body == BinaryPrimitives.ReadUInt64LittleEndian(bytes)
                && pointer.Context == BinaryPrimitives.ReadUInt64LittleEndian(bytes[8..]),
                "Descriptor pair differs from independently linked bytes.");
            Assert(pointer.ContextKind != FunctionPointerContextKind.MethodTable
                || typeAddresses.Contains(pointer.Context), "Type context is not an EEType symbol.");
            Assert(pointer.ContextKind != FunctionPointerContextKind.MethodDictionary
                || symbols.Any(symbol => symbol.Address == pointer.Context
                    && symbol.Name.StartsWith("__GenericDict_", StringComparison.Ordinal)
                    && !typeAddresses.Contains(symbol.Address)), "Dictionary role disagrees with linker oracle.");
        }

        var independent = new FatFunctionPointers(image, header, memory, null, null);
        Assert(independent.References.All(reference => reference.Source == FatPointerSource.ClassConstructor)
            && independent.Values.Count > 0, "Constructor source incorrectly requires code/metadata analysis.");

        var direct = new GenericContextReferences(image, unwind, map).Values
            .Select(reference => reference.Context).ToHashSet();
        int added = result.Values.Count(pointer => pointer.ContextKind == FunctionPointerContextKind.MethodDictionary
            && !direct.Contains(pointer.Context));
        Assert(expectedPointers is null || result.Values.Count == expectedPointers, "Anchored producer coverage changed.");
        Assert(expectedDictionaries is null || added == expectedDictionaries, "Additional dictionary coverage changed.");

        int cases = ScopeCases(metadata, traces);
        FatFunctionPointerReference calli = result.References.Concat(result.UnprovenUses.Select(use => use.Reference))
            .FirstOrDefault(reference => reference.Source == FatPointerSource.IndirectCall);

        if (calli.Consumer != 0) {
            ulong pointer = result.Values[calli.PointerIndex].Pointer;
            var function = unwind.Entries.Take(unwind.DirectoryCount).Select(entry => entry.Function)
                .First(function => function.End - function.Begin >= 128
                    && map.Methods.Any(method => method.Begin == function.Begin
                        && method.Info?.CodeLength == function.End - function.Begin));
            int methodIndex = Array.FindIndex(map.Methods, method => method.Begin == function.Begin);
            var original = map.Methods[methodIndex];
            ulong start = image.ImageBase + function.Begin;
            int offset = image.FileRange(start).Start;

            static byte[] Join(params byte[][] arrays) => arrays.SelectMany(array => array).ToArray();

            byte[] Load(ulong value) {
                byte[] data = [0x48, 0xBB, 0, 0, 0, 0, 0, 0, 0, 0];
                BinaryPrimitives.WriteUInt64LittleEndian(data.AsSpan(2), value);

                return data;
            }

            void Case(
                byte[] prefix, byte[] between, byte[] call, int expected,
                byte test = 0xC3, byte condition = 0x74,
                ulong? literal = null, Action<RuntimeMemory>? corrupt = null,
                Action<byte[]>? editCode = null
            ) {
                byte[] bytes = (byte[])image.FileData.Clone();
                var code = bytes.AsSpan(offset, 128);
                code.Fill(0x90);
                prefix.CopyTo(code);
                Load(literal ?? pointer).CopyTo(code[prefix.Length..]);
                int check = prefix.Length + 10;
                code[check] = 0xF6;
                code[check + 1] = test;
                code[check + 2] = 2;
                code[check + 3] = condition;
                code[check + 4] = checked((byte)(between.Length + call.Length + 1));
                between.CopyTo(code[(check + 5)..]);
                call.CopyTo(code[(check + 5 + between.Length)..]);
                code[check + 5 + between.Length + call.Length] = 0xC3;
                code[check + 6 + between.Length + call.Length] = 0xC3;
                map.Methods[methodIndex] = original with { Info = new MethodGcInfo { CodeLength = 128 } };
                editCode?.Invoke(bytes);

                var changed = new PeImage(bytes);
                var changedMemory = new RuntimeMemory(changed, Hydration.Read(changed, header));
                corrupt?.Invoke(changedMemory);
                var actual = new FatFunctionPointers(changed, header, changedMemory, unwind, map);

                Assert(actual.References.Count(reference => reference.Source == FatPointerSource.IndirectCall
                    && reference.Owner == start) == expected, $"Incorrect calli proof in case {cases}.");
                ++cases;
            }

            byte[] context = [0x48, 0x8B, 0x4B, 6];
            byte[] near = [0xFF, 0x53, 0xFE];

            Case([], context, near, 1);
            Case([], context, [0x48, 0xFF, 0x5B, 0xFE], 0);
            Case([], context, near, 0, test: 0xC7); // BH tests a different byte from the tag.
            Case([], context, near, 0, condition: 0x75);
            Case([], context, near, 0, literal: pointer - 2);
            Case([], context, near, 0, literal: pointer + 1);
            Case([0xC3], context, near, 0);
            Case([], [0x48, 0x8B, 0x4B, 8], near, 0);
            Case([], [0x8B, 0x4B, 6], near, 0);
            Case([], Join([0x65], context), near, 0);
            Case([], context, [0xFF, 0x53, 0xF8], 0);
            Case([], Join(context, [0xB9, 0, 0, 0, 0]), near, 0);
            Case([], Join([0xBB, 0, 0, 0, 0], context), near, 0);
            Case([], Join(context, [0x48, 0x89, 0x43, 6]), near, 0);
            Case([], Join(context, [0x48, 0x89, 0xDE], [0x48, 0x89, 0x46, 6]), near, 0);
            Case([], Join(context, [0x48, 0x0F, 0xB1, 0x43, 0xFE]), near, 0);
            Case([], Join(context, [0x48, 0x8B, 0x43, 0xFE]), [0xFF, 0xD0], 1);
            Case([], Join(context, [0x8B, 0x43, 0xFE]), [0xFF, 0xD0], 0);
            Case(Join(Load(pointer), [0x48, 0x89, 0x43, 6]), context, near, 0);
            Case(Join(Load(pointer), [0x84, 0xC0, 0x75, 0], [0x48, 0x89, 0x43, 6]), context, near, 0);
            Case(Join(Load(pointer), [0x48, 0x8D, 0x03], [0x48, 0x89, 0x40, 6]), context, near, 0);

            byte[] ripStore = [0x48, 0x89, 0x05, 0, 0, 0, 0];
            BinaryPrimitives.WriteInt32LittleEndian(ripStore.AsSpan(3),
                checked((int)((long)pointer - 2 - (long)start - 7)));
            Case(ripStore, context, near, 0);

            RuntimeFunction mutator = unwind.Entries.Take(unwind.DirectoryCount).Select(entry => entry.Function)
                .First(candidate => candidate.Begin != function.Begin && candidate.End - candidate.Begin >= 16);
            ulong mutatorAddress = image.ImageBase + mutator.Begin;
            int mutatorOffset = image.FileRange(mutatorAddress).Start;
            byte[] forwarded = [0x48, 0xB9, 0, 0, 0, 0, 0, 0, 0, 0, 0xE8, 0, 0, 0, 0];
            BinaryPrimitives.WriteUInt64LittleEndian(forwarded.AsSpan(2), pointer - 2);
            BinaryPrimitives.WriteInt32LittleEndian(forwarded.AsSpan(11),
                checked((int)((long)mutatorAddress - (long)start - forwarded.Length)));
            void MutateDescriptor(byte[] bytes) {
                // The callee writes through the caller's forwarded descriptor alias.
                byte[] store = [0x48, 0xC7, 0x41, 8, 0, 0, 0, 0, 0xC3];
                store.CopyTo(bytes, mutatorOffset);
            }

            Case(forwarded, context, near, 0, editCode: MutateDescriptor);
            byte[] forwardedInterior = (byte[])forwarded.Clone();
            BinaryPrimitives.WriteUInt64LittleEndian(forwardedInterior.AsSpan(2), pointer + 6);
            Case(forwardedInterior, context, near, 0, editCode: bytes => {
                byte[] store = [0x48, 0xC7, 0x01, 0, 0, 0, 0, 0xC3];
                store.CopyTo(bytes, mutatorOffset);
            });
            byte[] fifthArgument = [0x48, 0x83, 0xEC, 0x38,
                0x48, 0xB8, 0, 0, 0, 0, 0, 0, 0, 0,
                0x48, 0x89, 0x44, 0x24, 0x20, 0xE8, 0, 0, 0, 0,
                0x48, 0x83, 0xC4, 0x38];
            BinaryPrimitives.WriteUInt64LittleEndian(fifthArgument.AsSpan(6), pointer - 2);
            BinaryPrimitives.WriteInt32LittleEndian(fifthArgument.AsSpan(20),
                checked((int)((long)mutatorAddress - (long)start - 24)));
            Case(fifthArgument, context, near, 0, editCode: bytes => {
                byte[] store = [0x48, 0x8B, 0x44, 0x24, 0x28, 0x48, 0xC7, 0x40, 8, 0, 0, 0, 0, 0xC3];
                store.CopyTo(bytes, mutatorOffset);
            });

            void CorruptField(RuntimeMemory target, int field, ulong value) {
                int index = target.Find(pointer - 2);
                var region = target.Regions[index];
                byte[] bytes = region.Data.ToArray();
                BinaryPrimitives.WriteUInt64LittleEndian(
                    bytes.AsSpan(checked((int)(pointer - 2 - region.Start)) + field), value);
                target.Regions[index] = new(region.Start, bytes, region.Writable, region.Hydrated);
            }

            var descriptor = result.Values[calli.PointerIndex];
            Case([], context, near, 0, corrupt: target => CorruptField(target, 0, 0));
            Case([], context, near, 0, corrupt: target => CorruptField(target, 0, descriptor.Body + 1));
            Case([], context, near, 0, corrupt: target => CorruptField(target, 0, descriptor.Body + 4));
            Case([], context, near, 0, corrupt: target => CorruptField(target, 8, 0));
            Case([], context, near, 0, corrupt: target => CorruptField(target, 8, descriptor.Context + 1));
            Case([], context, near, 0, corrupt: target => CorruptField(target, 8, descriptor.Body));
            Case([], context, near, 0, corrupt: target => {
                int index = target.Find(pointer - 2);
                var region = target.Regions[index];
                target.Regions[index] = new(region.Start, region.Data, true, false);
            });
            Case([], context, near, 0, corrupt: target => {
                int index = target.Find(pointer - 2);
                var region = target.Regions[index];
                target.Regions[index] = new(region.Start,
                    region.Data[..checked((int)(pointer - 2 - region.Start) + 15)], region.Writable, region.Hydrated);
            });

            map.Methods[methodIndex] = original;
        }

        Console.WriteLine($"Fat function pointers: {result.Values.Count}/{oracle.Count} producer descriptors, {result.References.Count} anchored references, {added} additional method dictionaries, zero oracle false positives; {cases} adverse cases passed.");
    }

    private static int ScopeCases(Metadata metadata, TraceMaps traces) {
        var trace = traces.Methods.FirstOrDefault(trace => trace.Name == "InitializeOpenStaticThunk");
        int scopeIndex = metadata.Scopes.FindIndex(scope => scope.Name != "System.Private.CoreLib");

        if (trace.Signature == 0 || scopeIndex < 0)
            return 0;

        var signature = metadata.SignatureBuilder.Methods[trace.Signature];
        int parameter = metadata.SignatureBuilder.Edges[signature.Parameters.Start + 1];
        var original = metadata.SignatureBuilder.Nodes[parameter];
        var foreign = metadata.Scopes[scopeIndex];

        Assert(ManagedFunctionPointerConsumers.Read(metadata, traces, metadata.SignatureBuilder.Publish())
            .Any(consumer => consumer.Target == trace.Entrypoint), "Healthy delegate consumer rejected.");

        metadata.SignatureBuilder.SetNode(parameter,
            original with { MetadataScope = (foreign.Offset << metadata.HandleBits) | 0x38 });
        Assert(ManagedFunctionPointerConsumers.Read(metadata, traces, metadata.SignatureBuilder.Publish())
            .All(consumer => consumer.Target != trace.Entrypoint), "Foreign same-name IntPtr accepted.");

        metadata.Scopes[scopeIndex] = foreign with { Name = "System.Private.CoreLib", Major = 99 };
        Assert(ManagedFunctionPointerConsumers.Read(metadata, traces, metadata.SignatureBuilder.Publish())
            .All(consumer => consumer.Target != trace.Entrypoint), "Different same-name CoreLib identity accepted.");

        metadata.SignatureBuilder.SetNode(parameter, original);
        metadata.Scopes[scopeIndex] = foreign;
        Assert(ManagedFunctionPointerConsumers.Read(metadata, traces, metadata.SignatureBuilder.Publish())
            .Any(consumer => consumer.Target == trace.Entrypoint), "Consumer state was not restored.");

        return 2;
    }

    private static void Assert(bool condition, string message) {
        if (!condition)
            throw new Exception(message);
    }
}
