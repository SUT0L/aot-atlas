using System.Buffers.Binary;
using System.Diagnostics;
using System.Text.RegularExpressions;
using Atlas;

internal static class GenericContextReferenceChecks {
    internal static void Benchmark(string imagePath) {
        var image = new PeImage(File.ReadAllBytes(imagePath));
        var header = ReadyToRun.Read(image);
        var analysis = new UnwindAnalysis(image, header, new RuntimeMemory(image, Hydration.Read(image, header)));
        var unwind = analysis.RequireUnwind();
        var map = new MethodGcMap(image, header, unwind, analysis.RequireManaged());
        var expected = new GenericContextReferences(image, unwind, map);

        for (int run = 0; run < 10; ++run)
            _ = new GenericContextReferences(image, unwind, map);

        double[] elapsed = new double[41];
        long[] allocated = new long[41];

        for (int run = 0; run < elapsed.Length; ++run) {
            long bytes = GC.GetAllocatedBytesForCurrentThread();
            long start = Stopwatch.GetTimestamp();

            var result = new GenericContextReferences(image, unwind, map);
            elapsed[run] = Stopwatch.GetElapsedTime(start).TotalMilliseconds;
            allocated[run] = GC.GetAllocatedBytesForCurrentThread() - bytes;

            Assert(result.Parameters.SequenceEqual(expected.Parameters) && result.Values.SequenceEqual(expected.Values),
                "Repeated context analysis changed its evidence.");
        }

        Array.Sort(elapsed);
        Array.Sort(allocated);
        Console.WriteLine($"Generic context analysis: median {elapsed[20]:F3} ms, p95 {elapsed[38]:F3} ms, median {allocated[20]} allocated bytes; {expected.Values.Count} references.");
    }

    internal static void Run(string imagePath, string mapPath) {
        var image = new PeImage(File.ReadAllBytes(imagePath));
        var header = ReadyToRun.Read(image);
        var section = header.Find(RtrSectionId.EmbeddedMetadata);
        var metadata = MetadataBuilder.FromImage(image, header);
        metadata.ReadDefinitions();

        var fixups = RuntimeTables.Fixups(image, header.Find(RtrSectionId.CommonFixupsTable));
        var maps = new ReflectionMaps();
        maps.Read(image, header, metadata, fixups);
        var extraction = new Extraction(image, header, metadata, maps, fixups);
        var gc = new MethodGcMap(image, header, extraction.Unwind, extraction.Managed);
        var references = new GenericContextReferences(image, extraction.Unwind, gc);

        var symbols = File.ReadLines(mapPath).Select(line => Regex.Match(line,
            @"^\s+\d{4}:[0-9a-fA-F]+\s+(\S+)\s+([0-9a-fA-F]{16})\s+Probe.obj"))
            .Where(match => match.Success)
            .Select(match => (Name: match.Groups[1].Value, Address: Convert.ToUInt64(match.Groups[2].Value, 16)))
            .ToArray();
        var typeNames = symbols.Where(symbol => symbol.Name.StartsWith("??_7", StringComparison.Ordinal)
            && symbol.Name.EndsWith("@@6B@", StringComparison.Ordinal))
            .Select(symbol => symbol.Name[4..^5]).ToHashSet();

        // Both dictionary categories use this prefix. Type dictionary names match
        // their independent EEType symbol; the remaining names identify methods.
        var oracle = symbols.Where(symbol => symbol.Name.StartsWith("__GenericDict_", StringComparison.Ordinal)
            && !typeNames.Contains(symbol.Name[14..])).Select(symbol => symbol.Address).ToHashSet();
        Assert(references.Values.Count > 20, "Expected useful method dictionary references.");
        Assert(references.Values.All(reference => oracle.Contains(reference.Context)),
            "Context inference introduced a non-dictionary address.");

        foreach (var use in references.Values) {
            var parameter = references.Parameters[use.ParameterIndex];
            Assert(parameter.Target == use.Target && parameter.Register is 1 or 2 or 8 or 9,
                "Invalid context argument provenance.");
            Assert(parameter.GcInfoRva != 0 && parameter.Store < parameter.Target + 64,
                "Missing bounded GC/prologue witness.");
        }

        int methodIndex = Array.FindIndex(gc.Methods,
            method => image.ImageBase + method.Begin == references.Parameters[0].Target);
        var method = gc.Methods[methodIndex];
        ulong target = image.ImageBase + method.Begin;
        int targetFile = image.FileRange(target).Start;
        int targetLength = checked((int)(method.End - method.Begin));

        var function = extraction.Unwind.Entries.Take(extraction.Unwind.DirectoryCount)
            .Select(entry => entry.Function)
            .First(candidate => candidate.End - candidate.Begin >= 128
                && image.ImageBase + candidate.End < target
                && gc.Methods.Any(row => row.Begin == candidate.Begin && row.Info is { } data
                    && data.CodeLength == candidate.End - candidate.Begin));
        int callerIndex = Array.FindIndex(gc.Methods, row => row.Begin == function.Begin);
        var callerMethod = gc.Methods[callerIndex];
        ulong start = image.ImageBase + function.Begin;
        int file = image.FileRange(start).Start;
        int length = checked((int)(function.End - function.Begin));

        ulong dictionary = references.Values[0].Context;
        int cases = 0;

        static byte[] Join(params byte[][] values) => values.SelectMany(value => value).ToArray();

        byte[] Load(int register, ulong? address = null) {
            byte[] bytes = new byte[10];
            bytes[0] = (byte)(register >= 8 ? 0x49 : 0x48);
            bytes[1] = (byte)(0xB8 + (register & 7));
            BinaryPrimitives.WriteUInt64LittleEndian(bytes.AsSpan(2), address ?? dictionary);

            return bytes;
        }

        void Case(
            byte[] prologue, byte[] prefix, byte[] suffix,
            int register, int expected, int frame = -1, int slot = 32
        ) {
            byte[] bytes = (byte[])image.FileData.Clone();
            bytes.AsSpan(targetFile, Math.Min(targetLength, 64)).Fill(0x90);
            prologue.CopyTo(bytes, targetFile);
            bytes[targetFile + prologue.Length] = 0xC3;

            bytes.AsSpan(file, length).Fill(0x90);
            prefix.CopyTo(bytes, file);
            int call = prefix.Length;
            bytes[file + call] = 0xE8;
            BinaryPrimitives.WriteInt32LittleEndian(bytes.AsSpan(file + call + 1),
                checked((int)((long)target - (long)start - call - 5)));
            suffix.CopyTo(bytes, file + call + 5);

            gc.Methods[methodIndex] = method with {
                Info = new MethodGcInfo {
                    Flags = 0x20,
                    ValidRangeStart = (uint)prologue.Length,
                    CodeLength = (uint)targetLength,
                    GenericContextSlot = slot,
                    StackBaseRegister = frame
                }
            };
            gc.Methods[callerIndex] = callerMethod with {
                Info = new MethodGcInfo { CodeLength = (uint)length }
            };

            var changed = new PeImage(bytes);
            var result = new GenericContextReferences(changed, extraction.Unwind, gc);
            var parameters = result.Parameters.Where(parameter => parameter.Target == target).ToArray();

            Assert(register < 0 ? parameters.Length == 0
                : parameters.Length == 1 && parameters[0].Register == register,
                $"Incorrect prologue parameter in case {cases}.");
            Assert(result.Values.Count(reference => reference.Instruction >= start
                && reference.Instruction < start + (uint)length) == expected,
                $"Incorrect caller evidence in case {cases}.");
            ++cases;
        }

        byte[] rcx = [0x48, 0x89, 0x4C, 0x24, 0x20];

        Case(rcx, Load(1), [0xC3], 1, 1);
        Case(Join([0x5C], rcx), Load(1), [0xC3], -1, 0);
        Case(Join([0x53], rcx), Load(1), [0xC3], 1, 1);
        Case(Join([0x58], rcx), Load(1), [0xC3], 1, 1);
        Case([0x48, 0x89, 0x4C, 0x24, 0xE0], Load(1), [0xC3], 1, 1, -1, -32);
        Case([0x48, 0x89, 0x54, 0x24, 0x20], Load(2), [0xC3], 2, 1);
        Case([0x4C, 0x89, 0x44, 0x24, 0x20], Load(8), [0xC3], 8, 1);
        Case([0x4C, 0x89, 0x4C, 0x24, 0x20], Load(9), [0xC3], 9, 1);
        Case(Join([0x48, 0x89, 0xCB], [0x48, 0x89, 0x5C, 0x24, 0x20]), Load(1), [0xC3], 1, 1);
        Case(Join([0xB9, 0, 0, 0, 0], rcx), Load(1), [0xC3], -1, 0);
        Case(Join([0xFF, 0xD0], rcx), Load(1), [0xC3], -1, 0);
        Case(Join([0x74, 0], rcx), Load(1), [0xC3], -1, 0);
        Case(Join([0x65], rcx), Load(1), [0xC3], -1, 0);
        Case([0x48, 0x89, 0x4C, 0x24, 0x18], Load(1), [0xC3], -1, 0);
        Case([0x48, 0x89, 0x4D, 0x20], Load(1), [0xC3], -1, 0, 5);
        Case(rcx, Load(1), [0xC3], -1, 0, 16);
        Case(rcx, Load(1), [0xC3], -1, 0, -2);
        Case(Join([0x48, 0x8D, 0x6C, 0x24, 0x28], [0x48, 0x89, 0x4D, 0x20]), Load(1), [0xC3], 1, 1, 5);
        Case(Join([0x48, 0x8D, 0x6C, 0x24, 0x28], [0x48, 0x89, 0x4D, 0xE0]), Load(1), [0xC3], 1, 1, 5, -32);
        Case(Join(rcx, [0x90]), Load(1), [0xC3], 1, 1);
        Case(Join(rcx, [0x48, 0x83, 0xEC, 8]), Load(1), [0xC3], 1, 1, slot: 40);
        Case(Join(rcx, [0x48, 0x83, 0xEC, 8]), Load(1), [0xC3], -1, 0);
        Case(Join(rcx, [0x66, 0x50, 0x66, 0x50, 0x66, 0x50, 0x66, 0x50]), Load(1), [0xC3], 1, 1, slot: 40);
        Case(Join(rcx, [0xC6, 0x44, 0x24, 0x21, 0]), Load(1), [0xC3], -1, 0);
        Case(Join(rcx, [0xC6, 0x44, 0x24, 0x28, 0]), Load(1), [0xC3], 1, 1);
        Case(Join(rcx, [0x48, 0x89, 0xE7, 0xC6, 0x47, 0x21, 0]), Load(1), [0xC3], -1, 0);
        Case(Join(rcx, [0xC6, 0, 0]), Load(1), [0xC3], -1, 0);
        Case(Join(rcx, [0x48, 0x89, 0xC4]), Load(1), [0xC3], -1, 0);
        Case(Join(rcx, [0x48, 0x83, 0xC4, 8]), Load(1), [0xC3], 1, 1, slot: 24);
        Case(Join(rcx, [0x48, 0x89, 0xD1]), Load(1), [0xC3], 1, 1);
        Case(Join(rcx, [0x48, 0x8D, 0x7C, 0x24, 0x10, 0xB9, 17, 0, 0, 0, 0xF3, 0xAA]), Load(1), [0xC3], -1, 0);
        Case(Join(rcx, [0x48, 0x8D, 0x7C, 0x24, 0x10, 0x0F, 0xAE, 0x27]), Load(1), [0xC3], -1, 0);
        Case([0x89, 0x4C, 0x24, 0x20], Load(1), [0xC3], -1, 0);
        Case(rcx, Load(2), [0xC3], 1, 0);
        Case(rcx, Join([0xC3], Load(1)), [0xC3], 1, 0);
        Case(rcx, Join([0x84, 0xC0, 0x75, 0x10], Load(1)), [0xC3, 0xFF, 0xE0], 1, 0);
        Case(rcx, Join([0xEB, 10], Load(1)), [0xC3], 1, 0);
        Case(rcx, Load(1), [0xEB, 0xF9], 1, 0);
        Case(rcx, Join(Load(1), [0x74, 0]), [0xC3], 1, 1);
        Case(rcx, Join(Load(1), [0xEB, 0]), [0xC3], 1, 1); // A jump preserves the literal.
        Case(rcx, Join([0x84, 0xC0, 0x74, 12], Load(1), [0xEB, 10], Load(1)), [0xC3], 1, 1); // Both arms define the same context.
        Case(rcx, Join([0x84, 0xC0, 0x74, 12], Load(1), [0xEB, 10], Load(1, dictionary + 8)), [0xC3], 1, 0); // The arms disagree.
        Case(rcx, Join([0x84, 0xC0, 0x75, 10], Load(1)), [0xC3], 1, 0); // One arm has no definition.
        Case(rcx, Join([0x84, 0xC0, 0x74, 12], Load(3), [0xEB, 10], Load(3), [0x48, 0x89, 0xD9]), [0xC3], 1, 1); // Copy the equal joined value from RBX.
        Case(rcx, Join(Load(1), [0xEB, 10], Load(1, dictionary + 8)), [0xC3], 1, 1); // The conflicting definition is unreachable.
        Case(rcx, Join(Load(1), [0x84, 0xC0, 0x75, 0xFC]), [0xC3], 1, 1); // The backedge preserves RCX.
        Case(rcx, Join(Load(1), [0xEB, 2, 0x31, 0xC9, 0x84, 0xC0, 0x75, 0xFA]), [0xC3], 1, 0); // A later backedge clears RCX.
        Case(rcx, Join(Load(1), [0x74, 0, 0xB1, 1]), [0xC3], 1, 0); // A partial write follows the join.
        Case(rcx, Join(Load(1), [0x74, 0, 0x48, 0x0F, 0x44, 0xC8]), [0xC3], 1, 0); // A conditional write follows the join.
        Case(rcx, Join(Load(1), [0xFF, 0xD0]), [0xC3], 1, 0);
        Case(rcx, Join(Load(1), [0x48, 0x0F, 0x44, 0xC8]), [0xC3], 1, 0);

        for (int candidate = 0; candidate < 16; ++candidate) {
            if (candidate != 4)
                Case(rcx, Load(candidate), [0xC3], 1, candidate == 1 ? 1 : 0);
        }

        int duplicateIndex = methodIndex == 0 ? 1 : 0;
        var duplicate = gc.Methods[duplicateIndex];
        byte[] contradictoryBytes = (byte[])image.FileData.Clone();
        byte[] twoStores = [0x48, 0x89, 0x4C, 0x24, 0x20, 0x48, 0x89, 0x54, 0x24, 0x28];
        twoStores.CopyTo(contradictoryBytes, targetFile);
        gc.Methods[methodIndex] = method with {
            Info = new MethodGcInfo {
                Flags = 0x20,
                ValidRangeStart = 5,
                CodeLength = (uint)targetLength,
                GenericContextSlot = 32
            }
        };
        gc.Methods[duplicateIndex] = method with {
            Info = new MethodGcInfo {
                Flags = 0x20,
                ValidRangeStart = 10,
                CodeLength = (uint)targetLength,
                GenericContextSlot = 40
            }
        };

        var contradictory = new GenericContextReferences(new PeImage(contradictoryBytes), extraction.Unwind, gc);
        Assert(contradictory.Parameters.All(parameter => parameter.Target != target)
            && contradictory.Values.All(reference => reference.Target != target),
            "Contradictory ABI leaked a published parameter or caller inference.");

        gc.Methods[duplicateIndex] = duplicate;
        ++cases;
        gc.Methods[methodIndex] = method;
        gc.Methods[callerIndex] = callerMethod;

        foreach (var invalid in new[] {
            method with { End = method.Begin + 1 },
            method with { End = method.Begin },
            method with { End = method.Begin - 1 },
            method with { Info = new MethodGcInfo { CodeLength = 0, Flags = 0x20 } },
            method with { Info = new MethodGcInfo { CodeLength = uint.MaxValue, Flags = 0x20 } }
        }) {
            gc.Methods[methodIndex] = invalid;

            var withheld = new GenericContextReferences(image, extraction.Unwind, gc);
            Assert(withheld.Parameters.All(parameter => parameter.Target != target)
                && withheld.Values.All(reference => reference.Target != target),
                "A contradictory callee extent published a parameter or caller inference.");
        }

        gc.Methods[methodIndex] = method;

        var functions = extraction.Unwind.Entries.Take(extraction.Unwind.DirectoryCount)
            .Select(entry => entry.Function).ToArray();
        int logicalIndex = Array.FindIndex(gc.Methods, row => row.Info is { } info
            && functions.Any(root => root.Begin == row.Begin && root.End - root.Begin >= 32
                && info.CodeLength > root.End - root.Begin)
            && functions.Any(child => child.Begin > row.Begin && child.End - child.Begin >= 5
                && (ulong)child.Begin < (ulong)row.Begin + info.CodeLength)
            && row.Begin != method.Begin);
        Assert(logicalIndex >= 0, "Fixture lacks a logical method with a separately callable funclet.");

        var logical = gc.Methods[logicalIndex];
        var funclet = functions.First(child => child.Begin > logical.Begin && child.End - child.Begin >= 5
            && (ulong)child.Begin < (ulong)logical.Begin + logical.Info!.CodeLength);
        ulong logicalStart = image.ImageBase + logical.Begin;
        int logicalFile = image.FileRange(logicalStart).Start;
        int logicalLength = checked((int)logical.Info!.CodeLength);

        for (int skipLoad = 0; skipLoad < 2; ++skipLoad) {
            byte[] bytes = (byte[])image.FileData.Clone();
            rcx.CopyTo(bytes, targetFile);
            bytes[targetFile + rcx.Length] = 0xC3;

            bytes.AsSpan(logicalFile, logicalLength).Fill(0x90);
            Load(1).CopyTo(bytes, logicalFile);
            bytes[logicalFile + 10] = 0xE8;
            BinaryPrimitives.WriteInt32LittleEndian(bytes.AsSpan(logicalFile + 11),
                checked((int)((long)target - (long)logicalStart - 15)));
            bytes[logicalFile + 15] = 0xC3;

            int childFile = image.FileRange(image.ImageBase + funclet.Begin).Start;
            bytes[childFile] = 0xE9;
            BinaryPrimitives.WriteInt32LittleEndian(bytes.AsSpan(childFile + 1),
                checked((int)((long)logical.Begin + skipLoad * 10 - funclet.Begin - 5)));
            gc.Methods[methodIndex] = method with {
                Info = new MethodGcInfo {
                    Flags = 0x20,
                    ValidRangeStart = 5,
                    CodeLength = (uint)targetLength,
                    GenericContextSlot = 32
                }
            };
            gc.Methods[logicalIndex] = logical with {
                Info = new MethodGcInfo { CodeLength = (uint)logicalLength }
            };

            var result = new GenericContextReferences(new PeImage(bytes), extraction.Unwind, gc);
            Assert(result.Values.Count(reference => reference.Instruction >= logicalStart
                && reference.Instruction < logicalStart + (uint)logicalLength) == 1 - skipLoad,
                "Funclet entry bypassed the context definition without invalidating its caller proof.");
            ++cases;
        }

        gc.Methods[methodIndex] = method;
        gc.Methods[logicalIndex] = logical;
        Console.WriteLine($"Generic context references: {references.Parameters.Length}/{references.DeclaredMethodContexts} prologue arguments, {references.Values.Count} uses, {references.Values.Select(reference => reference.Context).Distinct().Count()}/{oracle.Count} method dictionaries, zero oracle false positives; {cases} adverse cases passed.");
    }

    private static void Assert(bool condition, string message) {
        if (!condition)
            throw new Exception(message);
    }
}
