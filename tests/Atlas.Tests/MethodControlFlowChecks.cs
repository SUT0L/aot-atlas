using System.Buffers.Binary;
using System.Reflection;
using System.Diagnostics.CodeAnalysis;
using Atlas;
using Iced.Intel;

internal static class MethodControlFlowChecks {
    private const BindingFlags Hidden = BindingFlags.Instance | BindingFlags.NonPublic;

    [DynamicallyAccessedMembers(DynamicallyAccessedMemberTypes.NonPublicMethods | DynamicallyAccessedMemberTypes.NonPublicConstructors)]
    private static readonly Type ReaderType = Type.GetType("Atlas.MethodControlFlows, Atlas", throwOnError: true)!;

    [DynamicallyAccessedMembers(DynamicallyAccessedMemberTypes.NonPublicProperties | DynamicallyAccessedMemberTypes.NonPublicMethods)]
    private static readonly Type GraphType = Type.GetType("Atlas.MethodControlFlow, Atlas", throwOnError: true)!;

    private static readonly MethodInfo Read = ReaderType.GetMethod(
        "Read", Hidden, null, [typeof(MethodGcEntry).MakeByRefType()], null)!;

    private const ulong Owner = 0x140001000;

    internal static void Run() {
        int cases = 0;

        Check([0xC3, 0xFF, 0xE0], false, [true, false]);
        Check([0xFF, 0xE0], true, [true]);
        Check([0xC7, 0xF8, 0, 0, 0, 0, 0xC3], true, [true, false]);
        Check([0xEB, 1, 0x48, 0x89, 0xD8, 0xC3], true, [true, false, false]);
        Check([0xC3, 0xEB, 1, 0x48, 0x89, 0xD8], false, [true, false, false]);
        Check([0xEB, 0x7E], false, [true]);
        Check([0x74, 1, 0x90, 0xC3], false, [true, true, true]);
        Check([0x74, 0, 0xC3], false, [true, true]);

        var loop = Check([0x90, 0x75, 0xFD, 0xC3], false, [true, true, true]);
        Assert(Before(loop, Owner).SequenceEqual(new[] { true, true, false }),
            "A backedge was lost from reverse reachability.");
        Assert(ReferenceEquals(Before(loop, Owner), Before(loop, Owner)),
            "Repeated query does not share its immutable mask.");

        var joined = Check([0x74, 3, 0x90, 0xEB, 1, 0x90, 0xC3], false, [true, true, true, true, true]);
        Assert(Before(joined, Owner + 2).SequenceEqual(new[] { true, true, false, false, false }),
            "An unrelated branch entered a predecessor mask.");
        Assert(Before(joined, Owner + 6).All(value => value), "One predecessor of a join was discarded.");

        Check([0xC3, 0x90, 0x90, 0x90, 0xC3], false, [true, false, false, false, true], [0, 4]);
        Check([0x48, 0xB8, 1, 0, 0, 0, 0, 0, 0, 0, 0xC3], true, [true, true], [0, 1]);
        Check([0xC3], true, [false], [1]);

        var (reader, method) = Reader([0xC3, 0x90, 0x90, 0x90, 0xC3], [0, 4]);
        var first = Read.Invoke(reader, [method])!;
        Assert(ReferenceEquals(first, Read.Invoke(reader, [method])), "Owner/span cache did not retain its graph.");

        var other = method with { Begin = 0x1004, Info = new MethodGcInfo { CodeLength = 1 } };
        var second = Read.Invoke(reader, [other])!;
        Assert(!ReferenceEquals(first, second) && Code(first).Count == 5 && Code(second).Count == 1,
            "Another owner borrowed or overwrote the first decode.");

        var contradictory = method with { End = method.Begin + 1 };
        Assert(Read.Invoke(reader, [contradictory]) is null && ReferenceEquals(first, Read.Invoke(reader, [method])),
            "A contradictory owner extent reused or poisoned the validated span cache.");

        var shorter = method with { Info = new MethodGcInfo { CodeLength = 1 } };
        Assert(Code(Read.Invoke(reader, [shorter])!).Count == 1 && Code(first).Count == 5,
            "Distinct declared spans shared the wrong graph.");

        var invalid = Reader([0x0F], [0]);
        Assert(Read.Invoke(invalid.Reader, [invalid.Method]) is null, "Truncated decode was accepted.");

        var oversized = method with { Info = new MethodGcInfo { CodeLength = uint.MaxValue } };
        Assert(Read.Invoke(reader, [oversized]) is null, "Unbounded allocation from an invalid code extent.");

        RandomModel();
        Console.WriteLine($"Method control flow: {cases} hand-derived graphs, predecessor masks, independent roots, bounded decode, owner/span cache and retained graph lifetime passed.");

        object Check(byte[] bytes, bool unknown, bool[] reachable, int[]? roots = null) {
            var input = Reader(bytes, roots ?? [0]);
            var graph = Read.Invoke(input.Reader, [input.Method])!;

            Assert(graph is not null && (bool)Property(graph, "Unknown") == unknown,
                $"Unexpected control-flow status in case {cases}.");
            Assert(((IReadOnlyList<bool>)Property(graph!, "Reachability")).SequenceEqual(reachable),
                $"Unexpected reachable instructions in case {cases}.");

            ++cases;
            return graph!;
        }
    }

    private static void RandomModel() {
        var random = new Random(0xCF51A7);

        for (int sample = 0; sample < 256; ++sample) {
            const int count = 12;
            var kinds = Enumerable.Range(0, count).Select(_ => random.Next(9)).ToArray();
            kinds[7] = 7; // Five-byte MOV gives a guaranteed instruction-middle target.

            var offsets = new int[count + 1];

            for (int index = 0; index < count; ++index)
                offsets[index + 1] = offsets[index]
                    + (kinds[index] is 5 or 7 ? 5 : kinds[index] is 0 or 3 ? 1 : 2);

            var targets = Enumerable.Range(0, count).Select(_ => random.Next(count)).ToArray();
            byte[] bytes = new byte[offsets[^1]];
            var edges = new List<int>[count];
            var branchAddresses = new ulong[count];

            for (int index = 0; index < count; ++index) {
                edges[index] = new();
                int at = offsets[index];

                if (kinds[index] is 0 or 7 or 5 or 1 && index + 1 < count)
                    edges[index].Add(index + 1);

                if (kinds[index] is 1 or 2) {
                    edges[index].Add(targets[index]);
                    branchAddresses[index] = Owner + (uint)offsets[targets[index]];
                }

                switch (kinds[index]) {
                    case 0:
                        bytes[at] = 0x90;
                        break;

                    case 1:
                    case 2:
                        bytes[at] = kinds[index] == 1 ? (byte)0x75 : (byte)0xEB;
                        bytes[at + 1] = unchecked((byte)(offsets[targets[index]] - at - 2));
                        break;

                    case 3:
                        bytes[at] = 0xC3;
                        break;

                    case 4:
                        bytes[at] = 0xFF;
                        bytes[at + 1] = 0xE0;
                        break;

                    case 5:
                        bytes[at] = 0xE8;
                        BinaryPrimitives.WriteInt32LittleEndian(bytes.AsSpan(at + 1), 0x400 - at - 5);
                        break;

                    case 6:
                        bytes[at] = 0xEB;
                        bytes[at + 1] = 0x7F;
                        branchAddresses[index] = Owner + (uint)(at + 129);
                        break;

                    case 7:
                        bytes[at] = 0xB8;
                        break;

                    case 8:
                        bytes[at] = 0xEB;
                        bytes[at + 1] = unchecked((byte)(offsets[7] + 1 - at - 2));
                        branchAddresses[index] = Owner + (uint)offsets[7] + 1;
                        break;
                }
            }

            int[] roots = new[] { 0, random.Next(count), random.Next(count) }.Distinct().Order().ToArray();
            var expected = new bool[count];
            var pending = new Queue<int>(roots);

            while (pending.TryDequeue(out int index)) {
                if (expected[index])
                    continue;

                expected[index] = true;

                foreach (int next in edges[index])
                    pending.Enqueue(next);
            }

            bool unknown = Enumerable.Range(0, count).Any(index => expected[index] && kinds[index] is 4 or 8);
            var source = Reader(bytes, roots.Select(index => offsets[index]).ToArray());
            var graph = Read.Invoke(source.Reader, [source.Method])!;

            Assert((bool)Property(graph, "Unknown") == unknown
                && ((IReadOnlyList<bool>)Property(graph, "Reachability")).SequenceEqual(expected),
                $"Specification graph differs in random sample {sample}.");

            var joins = roots.Select(index => Owner + (uint)offsets[index]).ToHashSet();

            for (int index = 0; index < count; ++index)
                if (expected[index] && branchAddresses[index] != 0)
                    joins.Add(branchAddresses[index]);

            Assert(((IReadOnlySet<ulong>)Property(graph, "Joins")).SetEquals(joins),
                "Root/branch join set differs from independent labels.");

            if (unknown)
                continue;

            for (int target = 0; target < count; ++target) {
                var before = new bool[count];
                before[target] = expected[target];
                bool changed;

                do {
                    changed = false;

                    for (int index = 0; index < count; ++index) {
                        if (!before[index] && expected[index] && edges[index].Any(next => before[next])) {
                            before[index] = true;
                            changed = true;
                        }
                    }
                } while (changed);

                Assert(Before(graph, Owner + (uint)offsets[target]).SequenceEqual(before),
                    "Lazy predecessor mask differs from reference saturation.");
            }
        }

        Console.WriteLine("Method control flow: 256 specification-generated rooted graphs agree on reachable edges, joins, unknown targets and predecessor closure.");
    }

    internal static void Binary(string path) {
        var image = new PeImage(File.ReadAllBytes(path));
        var header = ReadyToRun.Read(image);
        var memory = new RuntimeMemory(image, Hydration.Read(image, header));
        var analysis = new UnwindAnalysis(image, header, memory);
        var unwind = analysis.RequireUnwind();
        var map = new MethodGcMap(image, header, unwind, analysis.RequireManaged());

        var direct = new GenericContextReferences(image, unwind, map);
        var seed = direct.Values.First();
        int index = Array.FindIndex(map.Methods, method => method.Info is { } info
            && seed.Instruction >= image.ImageBase + method.Begin
            && seed.Instruction - image.ImageBase - method.Begin < info.CodeLength);
        var prior = map.Methods[index];
        ulong owner = image.ImageBase + prior.Begin;

        byte[] bytes = (byte[])image.FileData.Clone();
        var code = bytes.AsSpan(image.FileRange(owner).Start, 128);
        code.Fill(0x90);
        int register = direct.Parameters[seed.ParameterIndex].Register;
        code[0] = (byte)(register >= 8 ? 0x49 : 0x48);
        code[1] = (byte)(0xB8 + (register & 7));
        BinaryPrimitives.WriteUInt64LittleEndian(code[2..], seed.Context);
        code[10] = 0xE8;
        BinaryPrimitives.WriteInt32LittleEndian(code[11..],
            checked((int)((long)seed.Target - (long)owner - 15)));
        code[15] = 0xFF;
        code[16] = 0xE0;
        map.Methods[index] = prior with { Info = new MethodGcInfo { CodeLength = 128 } };

        var changed = new PeImage(bytes);
        var literal = new GenericContextReferences(changed, unwind, map);
        var dictionaries = new DictionarySlotConsumers(changed,
            new RuntimeMemory(changed, Hydration.Read(changed, header)), unwind, map, []);

        Assert(literal.UnresolvedControlFlowOwners.Contains(owner)
            && !literal.Values.Any(value => value.Instruction >= owner && value.Instruction < owner + 128),
            "Reachable unknown branch did not withhold the direct seed owner.");
        Assert(dictionaries.UnresolvedOwners.Contains(owner),
            "Excluded seed discovery disappeared from dictionary availability.");

        code[15] = 0xC3;
        code[16] = 0x90;
        code[^1] = 0x0F;
        var undecodable = new PeImage(bytes);
        var failedLiteral = new GenericContextReferences(undecodable, unwind, map);
        var failedDictionaries = new DictionarySlotConsumers(undecodable,
            new RuntimeMemory(undecodable, Hydration.Read(undecodable, header)), unwind, map, []);

        Assert(failedLiteral.UnresolvedControlFlowOwners.Contains(owner)
            && failedDictionaries.UnresolvedOwners.Contains(owner),
            "A failed bounded decode disappeared from source or dependent availability.");

        map.Methods[index] = prior;
        Console.WriteLine("Method control-flow publication: a withheld NativeAOT seed remains visible in dependent dictionary analysis.");
    }

    private static object Property(object graph, string name)
        => GraphType.GetProperty(name, Hidden)!.GetValue(graph)!;

    private static IReadOnlyList<Instruction> Code(object graph)
        => (IReadOnlyList<Instruction>)Property(graph, "Instructions");

    private static IReadOnlyList<bool> Before(object graph, ulong instruction)
        => (IReadOnlyList<bool>)GraphType.GetMethod("Before", Hidden)!.Invoke(graph, [instruction])!;

    internal static object Decode(byte[] code, int[]? roots = null) {
        (object Reader, MethodGcEntry Method) input = Reader(code, roots ?? [0]);

        return Read.Invoke(input.Reader, [input.Method])!;
    }

    internal static IReadOnlyList<bool> Reachability(object graph)
        => (IReadOnlyList<bool>)Property(graph, "Reachability");

    private static (object Reader, MethodGcEntry Method) Reader(byte[] code, int[] roots) {
        const int fileDelta = 512 - 0x1000;
        byte[] bytes = new byte[0x3000];
        "MZ"u8.CopyTo(bytes);
        BinaryPrimitives.WriteUInt32LittleEndian(bytes.AsSpan(60), 64);
        "PE\0\0"u8.CopyTo(bytes.AsSpan(64));
        BinaryPrimitives.WriteUInt16LittleEndian(bytes.AsSpan(68), 0x8664);
        BinaryPrimitives.WriteUInt16LittleEndian(bytes.AsSpan(70), 1);
        BinaryPrimitives.WriteUInt16LittleEndian(bytes.AsSpan(84), 240);
        BinaryPrimitives.WriteUInt16LittleEndian(bytes.AsSpan(88), 0x20B);
        BinaryPrimitives.WriteUInt64LittleEndian(bytes.AsSpan(112), Owner - 0x1000);
        BinaryPrimitives.WriteUInt32LittleEndian(bytes.AsSpan(144), 0x5000);
        BinaryPrimitives.WriteUInt32LittleEndian(bytes.AsSpan(148), 512);
        BinaryPrimitives.WriteUInt32LittleEndian(bytes.AsSpan(196), 16);
        BinaryPrimitives.WriteUInt32LittleEndian(bytes.AsSpan(224), 0x2000);
        BinaryPrimitives.WriteUInt32LittleEndian(bytes.AsSpan(228), (uint)(roots.Length * 12));

        ".text"u8.CopyTo(bytes.AsSpan(328));
        BinaryPrimitives.WriteUInt32LittleEndian(bytes.AsSpan(336), (uint)bytes.Length - 512);
        BinaryPrimitives.WriteUInt32LittleEndian(bytes.AsSpan(340), 0x1000);
        BinaryPrimitives.WriteUInt32LittleEndian(bytes.AsSpan(344), (uint)bytes.Length - 512);
        BinaryPrimitives.WriteUInt32LittleEndian(bytes.AsSpan(348), 512);
        BinaryPrimitives.WriteUInt32LittleEndian(bytes.AsSpan(364), 0x60000020);
        code.CopyTo(bytes, 512);

        for (int index = 0; index < roots.Length; ++index) {
            var row = bytes.AsSpan(0x2000 + fileDelta + index * 12);
            BinaryPrimitives.WriteUInt32LittleEndian(row, (uint)(0x1000 + roots[index]));
            BinaryPrimitives.WriteUInt32LittleEndian(row[4..], (uint)(0x1040 + roots[index]));
            BinaryPrimitives.WriteUInt32LittleEndian(row[8..], 0x2400);
        }

        bytes[0x2400 + fileDelta] = 1;
        var image = new PeImage(bytes);
        var unwind = new UnwindTables(image);
        object reader = Activator.CreateInstance(ReaderType, Hidden, null, [image, unwind, CancellationToken.None], null)!;

        return (reader, new(0x1000, 0x1040, 0, new MethodGcInfo { CodeLength = (uint)code.Length }, null));
    }

    private static void Assert(bool condition, string message) {
        if (!condition)
            throw new Exception(message);
    }
}
