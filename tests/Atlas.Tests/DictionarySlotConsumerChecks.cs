using System.Buffers.Binary;
using System.Text.RegularExpressions;
using Atlas;

internal static class DictionarySlotConsumerChecks {
    internal static void Run(string imagePath, string mapPath, int expectedPointers, int expectedSlots) {
        var image = new PeImage(File.ReadAllBytes(imagePath));
        var header = ReadyToRun.Read(image);
        var memory = new RuntimeMemory(image, Hydration.Read(image, header));
        var analysis = new UnwindAnalysis(image, header, memory);
        var unwind = analysis.RequireUnwind();
        var gc = new MethodGcMap(image, header, unwind, analysis.RequireManaged());

        var section = header.Find(RtrSectionId.EmbeddedMetadata);
        var metadata = MetadataBuilder.FromImage(image, header);
        metadata.ReadDefinitions();
        var traces = new TraceMaps(image, header, metadata,
            RuntimeTables.Fixups(image, header.Find(RtrSectionId.CommonFixupsTable)));
        var consumers = ManagedFunctionPointerConsumers.Read(metadata.Publish(), traces, metadata.SignatureBuilder.Publish());
        var result = new FatFunctionPointers(image, header, memory, unwind, gc, consumers);

        Assert(result.Values.Count == expectedPointers, "Fat-pointer coverage changed.");
        var slots = result.DictionaryConsumers!;
        Assert(slots.InitialDelegateSlots.Count == expectedSlots, "Initial dictionary-slot coverage changed.");
        Assert(slots.InitialContextTransfers.All(transfer => transfer.Evidence == ImageValueUseEvidence.InitialImage)
            && slots.InitialDelegateSlots.All(slot => slot.Evidence == ImageValueUseEvidence.InitialImage)
            && slots.ContextTransfers.All(transfer => transfer.Evidence == ImageValueUseEvidence.PreservedFromRetainedRootEntries)
            && slots.DelegateSlots.All(slot => slot.Evidence == ImageValueUseEvidence.PreservedFromRetainedRootEntries),
            "Initial dictionary bytes became unconditional runtime context facts.");

        var symbols = File.ReadLines(mapPath).Select(line => Regex.Match(line,
            @"^\s+\d{4}:[0-9a-fA-F]+\s+(\S+)\s+([0-9a-fA-F]{16})\s+Probe.obj"))
            .Where(match => match.Success)
            .Select(match => (Name: match.Groups[1].Value, Address: Convert.ToUInt64(match.Groups[2].Value, 16)))
            .ToArray();
        var types = symbols.Where(symbol => symbol.Name.StartsWith("??_7", StringComparison.Ordinal)
            && symbol.Name.EndsWith("@@6B@", StringComparison.Ordinal))
            .Select(symbol => symbol.Name[4..^5]).ToHashSet();
        var dictionaries = symbols.Where(symbol => symbol.Name.StartsWith("__GenericDict_", StringComparison.Ordinal)
            && !types.Contains(symbol.Name[14..])).Select(symbol => symbol.Address).ToHashSet();
        var descriptors = symbols.Where(symbol => symbol.Name.StartsWith("__fat", StringComparison.Ordinal)
            && symbol.Name.Contains("pointer_", StringComparison.Ordinal))
            .Select(symbol => symbol.Address).ToHashSet();

        foreach (var transfer in slots.InitialContextTransfers) {
            Assert(dictionaries.Contains(transfer.Dictionary) && dictionaries.Contains(transfer.Value),
                "A context edge disagrees with the linker dictionary category.");
            Assert(transfer.Slot >= transfer.Dictionary && (transfer.Slot - transfer.Dictionary) % 8 == 0
                && BinaryPrimitives.ReadUInt64LittleEndian(memory.Read(transfer.Slot, 8)) == transfer.Value,
                "Context slot differs from independently linked bytes.");
            Assert(slots.Relations.Any(relation => relation.Owner == transfer.Owner
                && relation.Kind == DictionaryContextRelationKind.LoadedSlot
                && relation.Load == transfer.Load && relation.Instruction == transfer.Instruction
                && relation.Target == transfer.Target
                && relation.SlotOffset == transfer.Slot - transfer.Dictionary),
                "Initial context transfer lost its symbolic load relation.");
        }

        foreach (var slot in slots.InitialDelegateSlots) {
            Assert(dictionaries.Contains(slot.Dictionary) && descriptors.Contains(slot.Pointer - 2),
                "Unanchored dictionary pointer pair.");
            Assert(BinaryPrimitives.ReadUInt64LittleEndian(memory.Read(slot.Slot, 8)) == slot.Pointer,
                "Delegate slot differs from independently linked bytes.");
            Assert(slots.InitialContextTransfers.Any(transfer => transfer.Target == slot.Owner
                && transfer.Value == slot.Dictionary), "Missing dictionary lookup chain.");
        }

        Assert(result.Values.All(pointer => descriptors.Contains(pointer.Descriptor)), "Unanchored fat descriptor.");

        MethodGcEntry[] declaredOnly = gc.Methods.Select(method => method.Info is { } info && (info.Flags & 0x30) == 0x20
            ? method : method with { Info = null }).ToArray();
        MethodGcEntry[] savedOriginalMethods = (MethodGcEntry[])gc.Methods.Clone();
        declaredOnly.CopyTo(gc.Methods, 0);
        DictionarySlotConsumers symbolicOnly = new(image, memory, unwind, gc, consumers);
        savedOriginalMethods.CopyTo(gc.Methods, 0);
        Assert(symbolicOnly.ContextReferences.Values.Count == 0 && symbolicOnly.InitialContextTransfers.Count == 0
            && symbolicOnly.InitialDelegateSlots.Count == 0, "A missing dictionary seed became an initial image identity.");
        Assert(symbolicOnly.Relations.SequenceEqual(slots.Relations)
            && symbolicOnly.SlotAccesses.SequenceEqual(slots.SlotAccesses),
            "Symbolic dictionary evidence depends on a static dictionary address.");

        var old = new HashSet<(ulong, ulong)>();

        foreach (var reference in new GenericContextReferences(image, unwind, gc).Values)
            old.Add((reference.Target, reference.Context));

        int added = slots.InitialContextTransfers.Select(transfer => transfer.Value)
            .Where(dictionary => !old.Any(pair => pair.Item2 == dictionary)).Distinct().Count();
        int cases = 0;

        if (slots.InitialDelegateSlots.Count != 0) {
            DictionaryDelegateSlot sample = slots.InitialDelegateSlots[0];
            DictionaryContextTransfer incoming = slots.InitialContextTransfers.First(transfer => transfer.Target == sample.Owner
                && transfer.Value == sample.Dictionary);
            int methodIndex = Array.FindIndex(gc.Methods, method => image.ImageBase + method.Begin == sample.Owner);
            int parentIndex = Array.FindIndex(gc.Methods, method => image.ImageBase + method.Begin == incoming.Owner);
            int rootIndex = Array.FindIndex(gc.Methods, method => method.Info is { } info
                && sample.Seed >= image.ImageBase + method.Begin
                && sample.Seed - image.ImageBase - method.Begin < info.CodeLength);
            MethodGcEntry[] savedMethods = (MethodGcEntry[])gc.Methods.Clone();
            byte[] isolated = (byte[])image.FileData.Clone();

            for (int index = 0; index < gc.Methods.Length; ++index) {
                if (index != methodIndex && index != parentIndex && index != rootIndex)
                    gc.Methods[index] = gc.Methods[index] with { Info = null };
            }

            Write(sample.Owner, [0x48, 0x89, 0x54, 0x24, 0x20, 0x48, 0x89, 0xD3, 0x49, 0x89, 0xD8], sample.Stub);
            Write(incoming.Owner, [0x4C, 0x89, 0x44, 0x24, 0x20, 0x4C, 0x89, 0xC7, 0x48, 0x8B, 0x57, 8], sample.Owner);
            ulong seedOwner = image.ImageBase + savedMethods[rootIndex].Begin;
            byte[] seed = [0x49, 0xB8, 0, 0, 0, 0, 0, 0, 0, 0];
            BinaryPrimitives.WriteUInt64LittleEndian(seed.AsSpan(2), incoming.Dictionary);
            Write(seedOwner, seed, incoming.Owner);
            gc.Methods[methodIndex] = savedMethods[methodIndex] with {
                Info = new MethodGcInfo { Flags = 0x20, ValidRangeStart = 5, GenericContextSlot = 32, CodeLength = 128 }
            };
            gc.Methods[parentIndex] = savedMethods[parentIndex] with {
                Info = new MethodGcInfo { Flags = 0x20, ValidRangeStart = 5, GenericContextSlot = 32, CodeLength = 128 }
            };
            gc.Methods[rootIndex] = savedMethods[rootIndex] with { Info = new MethodGcInfo { CodeLength = 128 } };
            image = new(isolated);
            FatFunctionPointers closed = new(image, header, new RuntimeMemory(image, Hydration.Read(image, header)), unwind, gc, consumers);
            Assert(closed.DictionaryConsumers!.DelegateSlots.Any(slot => slot.Owner == sample.Owner),
                "Independent literal seed and two forwarding prefixes failed to establish conditional preservation.");

            void Write(ulong owner, byte[] prefix, ulong target) {
                int file = image.FileRange(owner).Start;
                Span<byte> body = isolated.AsSpan(file, 128);
                body.Fill(0x90);
                prefix.CopyTo(body);
                body[prefix.Length] = 0xE8;
                BinaryPrimitives.WriteInt32LittleEndian(body[(prefix.Length + 1)..],
                    checked((int)((long)target - (long)owner - prefix.Length - 5)));
                body[prefix.Length + 5] = 0xC3;
            }

            var original = gc.Methods[methodIndex];
            int offset = image.FileRange(sample.Owner).Start;

            void Case(byte[] before, byte[] after, int expected, bool save = true, ulong? target = null) {
                byte[] bytes = (byte[])image.FileData.Clone();
                var code = bytes.AsSpan(offset, 128);
                code.Fill(0x90);
                byte[] prologue = [0x48, 0x89, 0x54, 0x24, 0x20]; // Declared RDX context slot.
                prologue.CopyTo(code);
                int at = 5;

                if (save) {
                    new byte[] { 0x48, 0x89, 0xD3 }.CopyTo(code[at..]);
                    at += 3;
                }

                before.CopyTo(code[at..]);
                at += before.Length;
                new byte[] { 0x49, 0x89, 0xD8 }.CopyTo(code[at..]);
                at += 3; // R8 <- saved dictionary.
                code[at] = 0xE8;
                BinaryPrimitives.WriteInt32LittleEndian(code[(at + 1)..],
                    checked((int)((long)(target ?? sample.Stub) - (long)sample.Owner - at - 5)));
                at += 5;
                after.CopyTo(code[at..]);
                gc.Methods[methodIndex] = original with {
                    Info = new MethodGcInfo {
                        Flags = 0x20,
                        ValidRangeStart = 5,
                        GenericContextSlot = 32,
                        CodeLength = 128
                    }
                };

                var changed = new PeImage(bytes);
                var changedResult = new FatFunctionPointers(changed, header,
                    new RuntimeMemory(changed, Hydration.Read(changed, header)), unwind, gc, consumers);

                Assert(changedResult.References.Count(reference =>
                    reference.Source == FatPointerSource.DictionarySlotDelegate
                    && reference.Owner == sample.Owner) == expected, $"Incorrect slot proof in case {cases}.");
                ++cases;
            }

            int count = closed.DictionaryConsumers.DelegateSlots.Count(slot => slot.Owner == sample.Owner);

            Case([], [0xC3], count);
            Case([0x84, 0xC0, 0x75, 0], [0xC3], count); // Both predecessors preserve RBX.
            Case([0x48, 0x85, 0xDB], [0xC3], count); // TEST reads; it does not kill origin.
            Case([0xBB, 0, 0, 0, 0], [0xC3], 0);
            Case([0x48, 0x0F, 0x44, 0xD8], [0xC3], 0);
            Case([], [0xC3], 0, save: false);
            Case([0xC3], [0xC3], 0);
            Case([], [0xC3], 0, target: sample.Stub + 1);
            Case([0xFF, 0xD0], [0xC3], 0); // Preserving a register does not close an unknown callee's global writes.
            Case([0xFF, 0xE0], [0xC3], 0); // Unknown internal targets invalidate owner proof.
            Case([0xC6, 0, 0], [0xC3], 0); // Unresolved prior write can alias any image slot.
            Case([], [0xC6, 0, 0, 0xC3], count); // A later acyclic write cannot precede this read.
            Case([], [0xC6, 0, 0, 0xEB, 0xF3], 0); // Same later write reaches this read through a backedge.
            Case([], [0xEB, 0xF6], 0); // RBX survives, but a prior delegate consumer's effects precede the next use.
            Case([0x84, 0xC0, 0x75, 3, 0xC6, 0, 0], [0xC3], 0);
            Case([], [0xBB, 0, 0, 0, 0, 0xEB, 0xF1], 0); // A later loop join invalidates RBX origin.
            Case([0x84, 0xC0, 0x75, 3, 0x48, 0x89, 0xD3], [0xC3], 0, save: false);
            Case([0xC6, 0x44, 0x24, 0x18, 0], [0xC3], count);
            Case([0x48, 0x89, 0xDC, 0xC6, 0x04, 0x24, 0], [0xC3], 0); // RSP may now alias the dictionary.

            byte[] LoadRdi(ulong value) {
                byte[] bytes = [0x48, 0xBF, 0, 0, 0, 0, 0, 0, 0, 0];
                BinaryPrimitives.WriteUInt64LittleEndian(bytes.AsSpan(2), value);

                return bytes;
            }

            Case(LoadRdi(sample.Slot - 8)
                .Concat(new byte[] { 0xB9, 2, 0, 0, 0, 0xF3, 0x48, 0xAB }).ToArray(), [0xC3], 0);
            Case(LoadRdi(sample.Pointer - 18)
                .Concat(new byte[] { 0xB9, 17, 0, 0, 0, 0xF3, 0xAA }).ToArray(), [0xC3], 0);
            Case(LoadRdi(sample.Slot + 8)
                .Concat(new byte[] { 0xB9, 9, 0, 0, 0, 0xFD, 0xF3, 0xAA }).ToArray(), [0xC3], 0);
            Case(LoadRdi(sample.Slot - 64).Concat(new byte[] { 0x0F, 0xAE, 0x27 }).ToArray(), [0xC3], 0);
            gc.Methods[methodIndex] = original;

            var parent = gc.Methods[parentIndex];
            int parentFile = image.FileRange(incoming.Owner).Start;

            void AncestorCase(byte[] before, byte[] after, int expected) {
                byte[] bytes = (byte[])image.FileData.Clone();
                var code = bytes.AsSpan(parentFile, 128);
                code.Fill(0x90);
                new byte[] { 0x4C, 0x89, 0x44, 0x24, 0x20, 0x4C, 0x89, 0xC7 }.CopyTo(code); // R8 -> GC slot, RDI.
                before.CopyTo(code[8..]);
                int at = 8 + before.Length;
                new byte[] { 0x48, 0x8B, 0x57, 8 }.CopyTo(code[at..]);
                at += 4;
                code[at] = 0xE8;
                BinaryPrimitives.WriteInt32LittleEndian(code[(at + 1)..],
                    checked((int)((long)sample.Owner - (long)incoming.Owner - at - 5)));
                after.CopyTo(code[(at + 5)..]);
                gc.Methods[parentIndex] = parent with {
                    Info = new MethodGcInfo {
                        Flags = 0x20,
                        ValidRangeStart = 5,
                        GenericContextSlot = 32,
                        CodeLength = 128
                    }
                };

                var changed = new PeImage(bytes);
                var actual = new FatFunctionPointers(changed, header,
                    new RuntimeMemory(changed, Hydration.Read(changed, header)), unwind, gc, consumers);

                Assert(actual.References.Count(reference =>
                    reference.Source == FatPointerSource.DictionarySlotDelegate
                    && reference.Owner == sample.Owner) == expected,
                    $"Incorrect ancestor-write proof in case {cases}.");
                ++cases;
            }

            AncestorCase([], [0xC3], count);
            AncestorCase([0xC6, 0, 0], [0xC3], 0);
            AncestorCase([], [0xC6, 0, 0, 0xC3], count);
            AncestorCase([], [0xC6, 0, 0, 0xEB, 0xF2], 0);
            gc.Methods[parentIndex] = parent;

            var root = gc.Methods[rootIndex];
            ulong rootStart = image.ImageBase + root.Begin;
            int rootFile = image.FileRange(rootStart).Start;

            void SeedCase(byte[] before, byte[] after, int expected) {
                byte[] bytes = (byte[])image.FileData.Clone();
                var code = bytes.AsSpan(rootFile, 128);
                code.Fill(0x90);
                before.CopyTo(code);
                int at = before.Length;
                code[at] = 0x49;
                code[at + 1] = 0xB8;
                BinaryPrimitives.WriteUInt64LittleEndian(code[(at + 2)..], incoming.Dictionary);
                at += 10;
                code[at] = 0xE8;
                BinaryPrimitives.WriteInt32LittleEndian(code[(at + 1)..],
                    checked((int)((long)incoming.Owner - (long)rootStart - at - 5)));
                after.CopyTo(code[(at + 5)..]);
                gc.Methods[rootIndex] = root with { Info = new MethodGcInfo { CodeLength = 128 } };

                var changed = new PeImage(bytes);
                var actual = new FatFunctionPointers(changed, header,
                    new RuntimeMemory(changed, Hydration.Read(changed, header)), unwind, gc, consumers);

                Assert(actual.References.Count(reference =>
                    reference.Source == FatPointerSource.DictionarySlotDelegate
                    && reference.Owner == sample.Owner) == expected,
                    $"Incorrect root-seed write proof in case {cases}.");
                ++cases;
            }

            SeedCase([], [0xC3], count);
            SeedCase([0xC6, 0, 0], [0xC3], 0);
            SeedCase([], [0xC6, 0, 0, 0xC3], count);
            SeedCase([], [0xC6, 0, 0, 0xEB, 0xEC], 0);
            savedMethods.CopyTo(gc.Methods, 0);
        }

        Console.WriteLine($"Dictionary consumers: {result.Values.Count}/{descriptors.Count} initial fat descriptors, {slots.InitialDelegateSlots.Count} initial delegate slots, {slots.InitialContextTransfers.Count} initial context edges/{added} additional dictionaries; {slots.DelegateSlots.Count} conditional slots/{slots.ContextTransfers.Count} conditional edges; zero oracle false positives; {cases} isolated seed/ancestor/consumer cases passed.");
    }

    private static void Assert(bool condition, string message) {
        if (!condition)
            throw new Exception(message);
    }
}
