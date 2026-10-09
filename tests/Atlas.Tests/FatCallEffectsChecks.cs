using System.Buffers.Binary;
using System.Reflection;
using Atlas;

internal static class FatCallEffectsChecks {
    internal static void Run(string binary, string linkerMap) {
        PeImage image = new(File.ReadAllBytes(binary));
        ReadyToRun header = ReadyToRun.Read(image);
        RuntimeMemory memory = new(image, Hydration.Read(image, header));
        UnwindAnalysis analysis = new(image, header, memory);
        UnwindTables unwind = analysis.RequireUnwind();
        MethodGcMap map = new(image, header, unwind, analysis.RequireManaged());
        Dictionary<string, ulong> symbols = new(StringComparer.Ordinal);

        foreach (string line in File.ReadLines(linkerMap)) {
            string[] columns = line.Split((char[]?)null, StringSplitOptions.RemoveEmptyEntries);
            if (columns.Length >= 4 && columns[0].Contains(':') && columns[3] == "Probe.obj")
                symbols[columns[1]] = Convert.ToUInt64(columns[2], 16);
        }

        ulong consumer = symbols["Probe_Program__Consumer"];
        ulong helper = symbols["Probe_Program__Mutate"];
        ulong stringPointer = symbols.Single(symbol => symbol.Key.StartsWith("__fat", StringComparison.Ordinal)
            && symbol.Key.Contains("pointer_", StringComparison.Ordinal)
            && symbol.Key.Contains("<String>", StringComparison.Ordinal)).Value + 2;
        ulong objectPointer = symbols.Single(symbol => symbol.Key.StartsWith("__fat", StringComparison.Ordinal)
            && symbol.Key.Contains("pointer_", StringComparison.Ordinal)
            && symbol.Key.Contains("<Object>", StringComparison.Ordinal)).Value + 2;
        ulong initial = BinaryPrimitives.ReadUInt64LittleEndian(memory.Read(stringPointer + 6, 8));
        ulong replacement = BinaryPrimitives.ReadUInt64LittleEndian(memory.Read(objectPointer + 6, 8));
        Assert(initial != replacement && memory.Regions[memory.Find(stringPointer - 2)].Writable,
            "Native producer no longer has distinct writable hydrated dictionary contexts.");

        FatFunctionPointers original = new(image, header, memory, unwind, map);
        Assert(original.Values.Any(pointer => pointer.Pointer == stringPointer && pointer.Context == initial)
            && original.References.All(reference => reference.Owner != consumer)
            && original.UnprovenUses.Any(use => use.Reference.Owner == consumer),
            "No-argument native global mutator published an initial context as a call-site fact or lost its raw descriptor.");

        int helperIndex = Array.FindIndex(map.Methods, method => image.ImageBase + method.Begin == helper);
        int consumerIndex = Array.FindIndex(map.Methods, method => image.ImageBase + method.Begin == consumer);
        MethodGcEntry nested = map.Methods.First(method => method.Info is { CodeLength: >= 32 }
            && method.Begin != map.Methods[helperIndex].Begin && method.Begin != map.Methods[consumerIndex].Begin);
        ulong nestedAddress = image.ImageBase + nested.Begin;
        int helperOffset = image.FileRange(helper).Start;
        int consumerOffset = image.FileRange(consumer).Start;
        int nestedOffset = image.FileRange(nestedAddress).Start;
        int cases = 0;

        byte[] GlobalStore(ulong owner, ulong target) {
            byte[] store = [0x48, 0xC7, 0x05, 0, 0, 0, 0, 0, 0, 0, 0, 0xC3];
            BinaryPrimitives.WriteInt32LittleEndian(store.AsSpan(3), checked((int)((long)target - (long)owner - 11)));
            return store;
        }

        byte[] Transfer(ulong owner, ulong target, byte opcode = 0xE8) {
            byte[] call = [opcode, 0, 0, 0, 0, 0xC3];
            BinaryPrimitives.WriteInt32LittleEndian(call.AsSpan(1), checked((int)((long)target - (long)owner - 5)));
            return call;
        }

        byte[] Calls(ulong owner, params ulong[] targets) {
            byte[] code = new byte[targets.Length * 5 + 1];
            for (int index = 0; index < targets.Length; ++index)
                Transfer(owner + (uint)(index * 5), targets[index]).AsSpan(0, 5).CopyTo(code.AsSpan(index * 5));
            code[^1] = 0xC3;

            return code;
        }

        Case(GlobalStore(helper, stringPointer + 6), false);
        Case(GlobalStore(helper, objectPointer + 6), true);
        Case([0xC3], true);
        Case(Transfer(helper, nestedAddress), false, GlobalStore(nestedAddress, stringPointer + 6));
        Case(Transfer(helper, nestedAddress), true, GlobalStore(nestedAddress, objectPointer + 6));
        Case(Transfer(helper, nestedAddress, 0xE9), false, GlobalStore(nestedAddress, stringPointer + 6));
        Case(Transfer(helper, nestedAddress, 0xE9), true, [0xC3]);
        Case(Transfer(helper, helper), true);
        Case(Transfer(helper, nestedAddress), true, Transfer(nestedAddress, helper));
        Case(Transfer(helper, nestedAddress), false, RecursiveStore(nestedAddress, helper, stringPointer + 6));
        Case(Transfer(helper, nestedAddress), true, RecursiveStore(nestedAddress, helper, objectPointer + 6));
        Case([0xFF, 0xD0, 0xC3], false);
        Case([0xFF, 0x15, 0, 0, 0, 0, 0xC3], false);
        Case([0xC3], true, writerAfter: true);
        DeepCallees();
        CachedRecursiveWriter();
        CompletedRecursiveComponents();
        RepeatedConsumer();
        MutationBeforeOwnerEntry();
        IndependentRootPrefixes();
        RetryAfterFailure();

        Console.WriteLine($"Callee writes: native no-argument descriptor mutation withheld; raw initial context 0x{initial:X} retained separately from replacement 0x{replacement:X}; {cases} global, unrelated, nested, tail, recursive, indirect/import and after-consumer cases passed.");

        byte[] RecursiveStore(ulong owner, ulong target, ulong written) {
            byte[] bytes = new byte[17];
            Transfer(owner, target).AsSpan(0, 5).CopyTo(bytes);
            GlobalStore(owner + 5, written).CopyTo(bytes, 5);

            return bytes;
        }

        void DeepCallees() {
            MethodGcEntry[] chain = [map.Methods[helperIndex], .. map.Methods
                .Where(method => method.Info is { CodeLength: >= 12 }
                    && method.Begin != map.Methods[helperIndex].Begin
                    && method.Begin != map.Methods[consumerIndex].Begin
                    && unwind.Entries.Take(unwind.DirectoryCount).Count(entry => entry.Function.Begin >= method.Begin
                        && entry.Function.Begin - method.Begin < method.Info.CodeLength) == 1)
                .DistinctBy(method => method.Begin)
                .Take(39)];
            Assert(chain.Length == 40, "Native producer has too few bodies for the deep call chain.");

            Check([0xC3], true);
            ulong last = image.ImageBase + chain[^1].Begin;
            Check(GlobalStore(last, stringPointer + 6), false);
            Check(GlobalStore(last, objectPointer + 6), true);
            Check([0xFF, 0xD0, 0xC3], false);

            void Check(byte[] tail, bool proven) {
                byte[] bytes = (byte[])image.FileData.Clone();
                for (int index = 0; index < chain.Length; ++index) {
                    ulong owner = image.ImageBase + chain[index].Begin;
                    int offset = image.FileRange(owner).Start;
                    bytes.AsSpan(offset, checked((int)chain[index].Info!.CodeLength)).Fill(0x90);
                    byte[] code = index + 1 == chain.Length ? tail
                        : Transfer(owner, image.ImageBase + chain[index + 1].Begin);
                    code.CopyTo(bytes, offset);
                }

                PeImage changed = new(bytes);
                FatFunctionPointers actual = new(changed, header,
                    new RuntimeMemory(changed, Hydration.Read(changed, header)), unwind, map);
                Assert(actual.References.Count(reference => reference.Owner == consumer) == (proven ? 1 : 0)
                    && actual.UnprovenUses.Count(use => use.Reference.Owner == consumer) == (proven ? 0 : 1),
                    $"Incorrect transitive effect at the end of a 40-body call chain in case {cases}.");
                ++cases;
            }
        }

        void CachedRecursiveWriter() {
            MethodGcEntry third = map.Methods.First(method => method.Info is { CodeLength: >= 12 }
                && method.Begin != map.Methods[helperIndex].Begin
                && method.Begin != nested.Begin && method.Begin != map.Methods[consumerIndex].Begin);
            ulong thirdAddress = image.ImageBase + third.Begin;
            byte[] bytes = (byte[])image.FileData.Clone();
            Calls(helper, nestedAddress, thirdAddress).CopyTo(bytes, helperOffset);
            Transfer(nestedAddress, helper).CopyTo(bytes, nestedOffset);
            GlobalStore(thirdAddress, stringPointer + 6).CopyTo(bytes, image.FileRange(thirdAddress).Start);
            PeImage changed = new(bytes);
            const BindingFlags hidden = BindingFlags.Instance | BindingFlags.NonPublic;
            Type flowType = Type.GetType("Atlas.MethodControlFlows, Atlas", throwOnError: true)!;
            object flows = Activator.CreateInstance(flowType, hidden, null,
                [changed, unwind, CancellationToken.None], null)!;
            Type closureType = Type.GetType("Atlas.ImageWriteClosure, Atlas", throwOnError: true)!;
            object closure = Activator.CreateInstance(closureType, hidden, null,
                [changed, flows, map, CancellationToken.None], null)!;
            MethodInfo query = closureType.GetMethod("MayWrite", hidden)!;

            // The recursive member is visited before a different outgoing edge
            // reaches the writer. It must remain unsafe when queried separately.
            foreach (ulong target in new[] { helper, nestedAddress, helper, nestedAddress }) {
                object graph = MethodControlFlowChecks.Decode(Transfer(0x140001000, target));
                Assert((bool)query.Invoke(closure, [graph, MethodControlFlowChecks.Reachability(graph),
                    stringPointer - 2, 16, 0UL])!, "A later recursive writer left a cached no-write member.");
            }
            ++cases;
        }

        void CompletedRecursiveComponents() {
            MethodGcEntry[] bodies = map.Methods.Where(method => method.Info is { CodeLength: >= 12 }
                && unwind.Entries.Take(unwind.DirectoryCount).Count(entry => entry.Function.Begin >= method.Begin
                    && entry.Function.Begin - method.Begin < method.Info.CodeLength) == 1)
                .DistinctBy(method => method.Begin).OrderBy(method => method.Begin).Take(6).ToArray();
            Assert(bodies.Length == 6, "Native producer has too few independent bodies for component closure.");
            ulong[] owners = bodies.Select(method => image.ImageBase + method.Begin).ToArray();
            ulong root = owners[0];
            ulong writer = owners[1];
            ulong first = owners[2];
            ulong second = owners[3];
            ulong chain = owners[4];
            ulong tail = owners[5];

            foreach (bool cycleWrites in new[] { false, true }) {
                Check(cycleWrites, [root, first, second, root]);
                Check(cycleWrites, [first, root, second, first]);
                Check(cycleWrites, [second, root, first, second]);
            }
            Check(false, [], completedUnavailable: true);
            Check(false, [], pendingUnavailable: true);

            void Check(bool cycleWrites, ulong[] order, bool completedUnavailable = false, bool pendingUnavailable = false) {
                byte[] bytes = (byte[])image.FileData.Clone();
                byte[][] code = [
                    pendingUnavailable ? Calls(root, writer, first) : Calls(root, first, chain),
                    GlobalStore(writer, stringPointer + 6),
                    Calls(first, second),
                    cycleWrites ? Calls(second, first, tail) : Calls(second, first),
                    Calls(chain, writer),
                    cycleWrites ? GlobalStore(tail, stringPointer + 6) : [0xC3]
                ];
                for (int index = 0; index < bodies.Length; ++index) {
                    int offset = image.FileRange(owners[index]).Start;
                    bytes.AsSpan(offset, checked((int)bodies[index].Info!.CodeLength)).Fill(0x90);
                    code[index].CopyTo(bytes, offset);
                }

                PeImage changed = new(bytes);
                const BindingFlags hidden = BindingFlags.Instance | BindingFlags.NonPublic;
                Type flowType = Type.GetType("Atlas.MethodControlFlows, Atlas", throwOnError: true)!;
                object flows = Activator.CreateInstance(flowType, hidden, null,
                    [changed, unwind, CancellationToken.None], null)!;
                Type closureType = Type.GetType("Atlas.ImageWriteClosure, Atlas", throwOnError: true)!;
                object closure = Activator.CreateInstance(closureType, hidden, null,
                    [changed, flows, map, CancellationToken.None], null)!;
                MethodInfo query = closureType.GetMethod("MayWrite", hidden)!;

                foreach (ulong target in order)
                    Assert(Query(target) == (target == root || cycleWrites),
                        "A pure component or its queued writer changed truth with query order.");

                if (completedUnavailable || pendingUnavailable) {
                    int sectionIndex = changed.FindSection(first);
                    PeSection section = changed.Sections[sectionIndex];
                    int available = 0;
                    if (pendingUnavailable) {
                        Assert(changed.FindSection(root) == sectionIndex && changed.FindSection(writer) == sectionIndex
                            && writer + bodies[1].Info!.CodeLength < first,
                            "Native component bodies cannot isolate an unavailable pending sibling.");
                        available = changed.FileRange(first).Start - section.FileOffset - 1;
                    } else {
                        Assert(Query(root), "The later writer was missed before completing its pure sibling.");
                    }

                    changed.Sections[sectionIndex] = new(section.Name, section.Rva, section.VirtualSize,
                        section.FileOffset, available, section.Characteristics);
                    try {
                        if (pendingUnavailable) {
                            // A known write already decides this query. An unread
                            // sibling must not turn that result into a read failure.
                            Assert(Query(root), "An unavailable pending sibling changed a known possible write.");
                        } else {
                            // The pure cycle was checked before a different branch
                            // reached the writer. Its closed proof survives lost reads.
                            Assert(!Query(first) && !Query(second),
                                "A completed pure cycle was discarded after a later writer.");
                        }
                    } finally {
                        changed.Sections[sectionIndex] = section;
                    }

                    Assert(!Query(first), "A restored pure sibling did not make progress after an unsafe root.");
                }
                ++cases;

                bool Query(ulong target) {
                    object graph = MethodControlFlowChecks.Decode(Transfer(0x140001000, target));

                    return (bool)query.Invoke(closure, [graph, MethodControlFlowChecks.Reachability(graph),
                        stringPointer - 2, 16, 0UL])!;
                }
            }
        }

        void Case(byte[] helperCode, bool proven, byte[]? nestedCode = null, bool writerAfter = false) {
            byte[] bytes = (byte[])image.FileData.Clone();
            bytes.AsSpan(helperOffset, checked((int)map.Methods[helperIndex].Info!.CodeLength)).Fill(0x90);
            helperCode.CopyTo(bytes, helperOffset);
            if (nestedCode is not null) {
                bytes.AsSpan(nestedOffset, checked((int)nested.Info!.CodeLength)).Fill(0x90);
                nestedCode.CopyTo(bytes, nestedOffset);
            }

            if (writerAfter) {
                // The write executes after the descriptor's calli context load/use.
                byte[] caller = [0x48, 0x83, 0xEC, 0x28,
                    0x48, 0xBB, 0, 0, 0, 0, 0, 0, 0, 0,
                    0xF6, 0xC3, 2, 0x74, 17,
                    0x48, 0x8B, 0x4B, 6, 0xFF, 0x53, 0xFE,
                    0xE8, 0, 0, 0, 0, 0x48, 0x83, 0xC4, 0x28, 0xC3, 0xC3];
                BinaryPrimitives.WriteUInt64LittleEndian(caller.AsSpan(6), stringPointer);
                BinaryPrimitives.WriteInt32LittleEndian(caller.AsSpan(27), checked((int)((long)helper - (long)consumer - 31)));
                bytes.AsSpan(consumerOffset, checked((int)map.Methods[consumerIndex].Info!.CodeLength)).Fill(0x90);
                caller.CopyTo(bytes, consumerOffset);
                GlobalStore(helper, stringPointer + 6).CopyTo(bytes, helperOffset);
            }

            PeImage changed = new(bytes);
            FatFunctionPointers actual = new(changed, header,
                new RuntimeMemory(changed, Hydration.Read(changed, header)), unwind, map);
            Assert(actual.Values.Any(pointer => pointer.Pointer == stringPointer && pointer.Context == initial),
                $"Initial descriptor disappeared in callee case {cases}.");
            Assert(actual.References.Count(reference => reference.Owner == consumer && reference.Source == FatPointerSource.IndirectCall)
                == (proven ? 1 : 0), $"Incorrect callee closure in case {cases}.");
            Assert(actual.UnprovenUses.Count(use => use.Reference.Owner == consumer)
                == (proven ? 0 : 1), $"Unproven call-site distinction disappeared in case {cases}.");
            ++cases;
        }

        void RetryAfterFailure() {
            byte[] bytes = (byte[])image.FileData.Clone();
            bytes[helperOffset] = 0xC3;
            PeImage retryImage = new(bytes);
            const BindingFlags hidden = BindingFlags.Instance | BindingFlags.NonPublic;
            Type flowType = Type.GetType("Atlas.MethodControlFlows, Atlas", throwOnError: true)!;
            object flows = Activator.CreateInstance(flowType, hidden, null,
                [retryImage, unwind, CancellationToken.None], null)!;
            MethodInfo read = flowType.GetMethods(hidden).Single(method => method.Name == "Read"
                && method.GetParameters().Length == 1 && method.GetParameters()[0].ParameterType.IsByRef);
            object graph = read.Invoke(flows, [map.Methods[consumerIndex]])!;
            ulong call = original.UnprovenUses.Single(use => use.Reference.Owner == consumer).Reference.Consumer;
            Type graphType = Type.GetType("Atlas.MethodControlFlow, Atlas", throwOnError: true)!;
            object before = graphType.GetMethod("Before", hidden)!.Invoke(graph, [call])!;
            Type closureType = Type.GetType("Atlas.ImageWriteClosure, Atlas", throwOnError: true)!;
            object closure = Activator.CreateInstance(closureType, hidden, null,
                [retryImage, flows, map, CancellationToken.None], null)!;
            MethodInfo query = closureType.GetMethod("MayWrite", hidden)!;
            int sectionIndex = retryImage.FindSection(helper);
            PeSection section = retryImage.Sections[sectionIndex];
            bool threw = false;

            // An unavailable helper read fails after its active entry is acquired.
            retryImage.Sections[sectionIndex] = new(section.Name, section.Rva, section.VirtualSize,
                section.FileOffset, 0, section.Characteristics);
            try {
                query.Invoke(closure, [graph, before, stringPointer - 2, 16, call]);
            } catch (TargetInvocationException error) when (error.InnerException is InvalidDataException) {
                threw = true;
            } finally {
                retryImage.Sections[sectionIndex] = section;
            }

            Assert(threw && !(bool)query.Invoke(closure, [graph, before, stringPointer - 2, 16, call])!,
                "A thrown helper read poisoned a later healthy proof as a recursive call.");
            ++cases;
        }

        void MutationBeforeOwnerEntry() {
            byte[] bytes = (byte[])image.FileData.Clone();
            // Consumer is pure, but Main changes its descriptor before entering it.
            bytes.AsSpan(consumerOffset + 5, 5).Fill(0x90);
            ulong main = symbols["Probe_Program__Main"];
            MethodGcEntry mainMethod = map.Methods.Single(method => image.ImageBase + method.Begin == main);
            byte[] mainCode = [0x48, 0x83, 0xEC, 0x28, 0xE8, 0, 0, 0, 0,
                0xE8, 0, 0, 0, 0, 0x48, 0x83, 0xC4, 0x28, 0xC3];
            BinaryPrimitives.WriteInt32LittleEndian(mainCode.AsSpan(5), checked((int)((long)helper - (long)main - 9)));
            BinaryPrimitives.WriteInt32LittleEndian(mainCode.AsSpan(10), checked((int)((long)consumer - (long)main - 14)));
            Assert(mainMethod.Info!.CodeLength >= mainCode.Length, "Native Main is too short for the independent entry-history challenger.");
            int offset = image.FileRange(main).Start;
            bytes.AsSpan(offset, checked((int)mainMethod.Info.CodeLength)).Fill(0x90);
            mainCode.CopyTo(bytes, offset);
            PeImage changed = new(bytes);
            FatFunctionPointers actual = new(changed, header,
                new RuntimeMemory(changed, Hydration.Read(changed, header)), unwind, map);
            FatFunctionPointerReference reference = actual.References.Single(reference => reference.Owner == consumer);
            Assert(reference.Evidence == ImageValueUseEvidence.PreservedFromOwnerEntry
                && actual.Values[reference.PointerIndex].Context == initial,
                "A closed pure prefix treated initialization as an unconditional runtime context after an earlier owner changed it.");
            ++cases;
        }

        void RepeatedConsumer() {
            byte[] bytes = (byte[])image.FileData.Clone();
            ulong body = BinaryPrimitives.ReadUInt64LittleEndian(memory.Read(stringPointer - 2, 8));
            MethodGcEntry bodyMethod = map.Methods.Single(method => image.ImageBase + method.Begin == body);
            byte[] loop = [0x53, 0x48, 0x83, 0xEC, 0x20, 0xBB, 2, 0, 0, 0,
                0x48, 0xB8, 0, 0, 0, 0, 0, 0, 0, 0, 0xA8, 2, 0x74, 11,
                0x48, 0x8B, 0x48, 6, 0xFF, 0x50, 0xFE, 0xFF, 0xCB, 0x75, 0xE7,
                0x48, 0x83, 0xC4, 0x20, 0x5B, 0xC3];
            BinaryPrimitives.WriteUInt64LittleEndian(loop.AsSpan(12), stringPointer);
            byte[] store = [0x48, 0xB8, 0, 0, 0, 0, 0, 0, 0, 0,
                0x48, 0x89, 0x05, 0, 0, 0, 0, 0xC3];
            BinaryPrimitives.WriteUInt64LittleEndian(store.AsSpan(2), replacement);
            BinaryPrimitives.WriteInt32LittleEndian(store.AsSpan(13),
                checked((int)((long)(stringPointer + 6) - (long)body - 17)));
            bytes.AsSpan(consumerOffset, checked((int)map.Methods[consumerIndex].Info!.CodeLength)).Fill(0x90);
            loop.CopyTo(bytes, consumerOffset);
            int bodyOffset = image.FileRange(body).Start;
            Assert(bodyMethod.Info!.CodeLength >= store.Length, "Native target body is too short for its descriptor update.");
            bytes.AsSpan(bodyOffset, checked((int)bodyMethod.Info.CodeLength)).Fill(0x90);
            store.CopyTo(bytes, bodyOffset);
            PeImage changed = new(bytes);
            FatFunctionPointers actual = new(changed, header,
                new RuntimeMemory(changed, Hydration.Read(changed, header)), unwind, map);
            Assert(actual.Values.Any(pointer => pointer.Pointer == stringPointer && pointer.Context == initial)
                && actual.References.All(reference => reference.Owner != consumer)
                && actual.UnprovenUses.Single(use => use.Reference.Owner == consumer).Reference.Evidence == ImageValueUseEvidence.Unproven,
                "A previous consumer invocation changed its descriptor before a repeated use but retained conditional preservation.");
            ++cases;
        }

        void IndependentRootPrefixes() {
            byte[] literal = [0x48, 0xB8, 0, 0, 0, 0, 0, 0, 0, 0, 0xA8, 2, 0x74, 7,
                0x48, 0x8B, 0x48, 6, 0xFF, 0x50, 0xFE, 0xC3];
            BinaryPrimitives.WriteUInt64LittleEndian(literal.AsSpan(2), stringPointer);

            CheckRoot(false);
            CheckRoot(true);

            void CheckRoot(bool unrelated) {
                byte[] bytes = (byte[])image.FileData.Clone();
                int length = checked((int)map.Methods[consumerIndex].Info!.CodeLength);
                bytes.AsSpan(consumerOffset, length).Fill(0x90);
                int rootOffset = unrelated ? 24 : 16;

                if (unrelated) {
                    literal.CopyTo(bytes, consumerOffset);
                    bytes[consumerOffset + rootOffset] = 0xC3;
                } else {
                    // An exceptional entry can follow a normal-owner mutation
                    // without a machine-code edge connecting the two prefixes.
                    GlobalStore(consumer, stringPointer + 6).CopyTo(bytes, consumerOffset);
                    literal.CopyTo(bytes, consumerOffset + rootOffset);
                }

                PeImage changed = new(bytes);
                UnwindTables roots = new(changed);
                int entryIndex = roots.Entries.FindIndex(entry => image.ImageBase + entry.Function.Begin == helper);
                UnwindEntry entry = roots.Entries[entryIndex];
                entry.Function = new(map.Methods[consumerIndex].Begin + (uint)rootOffset,
                    map.Methods[consumerIndex].End, entry.Function.Unwind);
                roots.Entries[entryIndex] = entry;
                roots.Entries.Sort(0, roots.DirectoryCount,
                    Comparer<UnwindEntry>.Create((left, right) => left.Function.Begin.CompareTo(right.Function.Begin)));
                FatFunctionPointers actual = new(changed, header,
                    new RuntimeMemory(changed, Hydration.Read(changed, header)), roots, map);
                FatFunctionPointerReference reference = actual.References.Single(reference => reference.Owner == consumer);
                ImageValueUseEvidence expected = unrelated ? ImageValueUseEvidence.PreservedFromOwnerEntry
                    : ImageValueUseEvidence.PreservedFromRetainedRootEntries;
                Assert(reference.Evidence == expected && actual.Values[reference.PointerIndex].Context == initial,
                    "An independent unwind root widened a normal-owner preservation claim or changed an unrelated prefix's condition.");
                ++cases;
            }
        }
    }

    private static void Assert(bool condition, string message) {
        if (!condition)
            throw new Exception(message);
    }
}
