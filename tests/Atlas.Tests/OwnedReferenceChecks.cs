using System.Diagnostics;
using System.Runtime.CompilerServices;
using Atlas;

internal static class OwnedReferenceChecks {
    internal static void Run() {
        var builder = new SignatureBuilder();
        var a = builder.Named("A");
        var b = builder.Named("B");
        var definition = builder.Named("Pair");
        var pair = builder.Instantiate(definition, [a, b]);
        var array = builder.Array(pair, 2, [2, 3], [-1, 0]);
        var method = builder.Method(a, [array], callingConvention: 0x20);
        var pointer = builder.FunctionPointer(b, [a], callingConvention: 4, nativeConvention: true);
        var variable = builder.Variable(1);
        var vector = builder.SzArray(a);
        var modified = builder.Modified(a, b);
        var graph = builder.Publish();
        Assert(array.In(graph).Render() == "Pair<A,B>[,]"
            && method.In(graph).Render("M") == "M(Pair<A,B>[,]) -> A"
            && pointer.In(graph).Render() == "delegate* unmanaged<A,B>");
        Assert(array.In(graph).ArraySizes.SequenceEqual(new[] { 2, 3 })
            && array.In(graph).ArrayLowerBounds.SequenceEqual(new[] { -1, 0 }));
        Assert(vector.In(graph).ArrayRank == 1 && variable.In(graph).VariablePosition == 1
            && variable.In(graph).Modifier.IsEmpty && a.In(graph).Element.IsEmpty
            && graph.Types[0].IsEmpty && graph.MethodSignatures[0].IsEmpty
            && modified.In(graph).Modifier.Render() == "B" && a.In(graph).Arguments.Count == 0
            && vector.In(graph).Name is null && default(SignatureMethods).Count == 0);
        Expect<ArgumentOutOfRangeException>(() => _ = default(SignatureMethods)[0]);
        Expect<InvalidOperationException>(() => _ = variable.In(graph).ArrayRank);
        Expect<InvalidOperationException>(() => _ = modified.In(graph).FunctionPointerConvention);
        Expect<InvalidOperationException>(() => _ = a.In(graph).VariablePosition);
        Expect<InvalidOperationException>(() => _ = a.In(graph).Optional);

        var foreignBuilder = new SignatureBuilder();
        var foreign = foreignBuilder.Named("Foreign");
        var foreignGraph = foreignBuilder.Publish();
        Reject(() => builder.Instantiate(definition, [a, foreign]));
        Reject(() => builder.Method(a, [b], varargs: [foreign]));
        Assert(ReferenceEquals(graph, builder.Publish()));
        Reject(() => a.In(foreignGraph));

        var mapBuilder = new ReflectionMapBuilder(graph);
        mapBuilder.Type(0x1000, a.In(graph));
        Reject(() => mapBuilder.Type(0x1000, foreign.In(foreignGraph)));
        Reject(() => mapBuilder.Type(0x1000, array.In(graph)));
        Reject(() => mapBuilder.Method(new() { Name = "M", DeclaringType = 0x1000 }, graph.MethodSignatures[0]));
        Reject(() => mapBuilder.Field(new() { Name = "F", DeclaringType = 0x1000 }, graph.Types[0]));
        Reject(() => mapBuilder.Method(default, method.In(graph)));
        Reject(() => mapBuilder.Field(default, a.In(graph)));
        var maps = mapBuilder.Publish();
        Assert(maps.MethodEntries.IsEmpty && maps.FieldEntries.IsEmpty);
        Expect<InvalidOperationException>(() => mapBuilder.Type(0x2000, b.In(graph)));
        var runtimeBuilder = new MethodTableBuilder();
        runtimeBuilder.Type(new() { Address = 0x1000, Flags = 0x50000000, BaseSize = 24 });
        var runtime = runtimeBuilder.Publish();
        var bindings = TypeBindings.Create(runtime, maps, graph);
        Assert(bindings.Resolve(a.In(graph)).Address == 0x1000
            && !bindings.Resolve(b.In(graph)).IsResolved);
        Reject(() => TypeBindings.Create(runtime, maps, foreignGraph));
        Reject(() => bindings.Resolve(foreign.In(foreignGraph)));

        var otherBindings = TypeBindings.Create(runtime, maps, graph);
        Reject(() => bindings.Resolve(a.In(graph), otherBindings.RuntimeType(0x1000)));
        Reject(() => bindings.Resolve(a.In(graph), methodArguments: [otherBindings.RuntimeType(0x1000)]));
        Assert(bindings.Resolve(a.In(graph), bindings.RuntimeType(0x1000)).Address == 0x1000);

        var retained = a.In(graph);
        var later = builder.Pointer(a);
        var extension = builder.Publish();
        Assert(retained.Render() == "A" && later.In(extension).Render() == "A*"
            && extension.Continue(retained).Render() == "A");
        Reject(() => extension.Continue(foreign.In(foreignGraph)));
        Reject(() => graph.Continue(later.In(extension)));
        Reject(() => bindings.Resolve(later.In(extension)));

        var preserved = graph.Types[a.Index];
        builder.SetNode(a.Index, new() { Kind = SignatureKind.Named, Name = "Changed" });
        Reject(() => builder.Publish().Continue(preserved));
        Reject(() => TypeBindings.Create(runtime, maps, builder.Publish()));
        Assert(preserved.Render() == "A" && bindings.Resolve(preserved).Address == 0x1000);
        Assert(Unsafe.SizeOf<SignatureType>() == 16 && Unsafe.SizeOf<SignatureMethod>() == 16
            && Unsafe.SizeOf<RuntimeTypeReference>() == 16 && Unsafe.SizeOf<SignatureNode>() == 64);
        Console.WriteLine("Owned references: foreign builders, graphs, map kinds, runtime owners and argument publications reject; discriminated facts and append continuation preserve retained identities while rewrites reject.");
    }

    internal static void Binary(string path) {
        var image = PeImage.ReadFile(path);
        var header = ReadyToRun.Read(image);
        var metadata = Metadata.FromImage(image, header);
        metadata.ReadDefinitions();
        var fixups = RuntimeTables.Fixups(image, header.Find(RtrSectionId.CommonFixupsTable));
        var maps = ReflectionMaps.Decode(image, header, metadata, fixups);
        var extraction = new Extraction(image, header, metadata, maps, fixups);
        var owned = new SignatureType[extraction.Maps.TypeEntries.Length];

        for (int i = 0; i < owned.Length; ++i) {
            owned[i] = extraction.Maps.TypeSignatureAt(i);
            Assert(extraction.Bindings.Resolve(owned[i]).Address == extraction.Maps.TypeEntries[i].MethodTable);
        }

        const int count = 200_000;
        long rawTicks = 0;
        long ownedTicks = 0;
        long rawAllocation = 0;
        long ownedAllocation = 0;
        ulong expected = 0;

        for (int run = 0; run < 8; ++run) {
            bool ownerFirst = (run & 1) != 0;
            var first = Measure(extraction, owned, count, ownerFirst);
            var second = Measure(extraction, owned, count, !ownerFirst);
            Assert(first.Sum == second.Sum);
            expected = first.Sum;

            if (run < 2)
                continue;

            rawTicks += ownerFirst ? second.Ticks : first.Ticks;
            ownedTicks += ownerFirst ? first.Ticks : second.Ticks;
            rawAllocation += ownerFirst ? second.Bytes : first.Bytes;
            ownedAllocation += ownerFirst ? first.Bytes : second.Bytes;
        }

        Console.WriteLine($"{Path.GetFileName(path)} owned native bindings: {owned.Length} exact type maps; 1.2M warm queries raw={rawTicks * 1000.0 / Stopwatch.Frequency:F3} ms/{rawAllocation} B, owned={ownedTicks * 1000.0 / Stopwatch.Frequency:F3} ms/{ownedAllocation} B; checksum={expected}.");
    }

    private static (long Ticks, long Bytes, ulong Sum) Measure(
        Extraction extraction,
        SignatureType[] references,
        int count,
        bool owned) {
        long allocated = GC.GetAllocatedBytesForCurrentThread();
        long start = Stopwatch.GetTimestamp();
        ulong sum = 0;

        for (int i = 0; i < count; ++i) {
            var signature = references[i % references.Length];

            if (owned) {
                sum += extraction.Bindings.Resolve(signature).Address;
            } else {
                int binding = extraction.Bindings.Resolve(signature.Index);
                sum += binding == 0 ? 0 : extraction.Types.Types[binding - 1].Address;
            }
        }

        return (Stopwatch.GetTimestamp() - start, GC.GetAllocatedBytesForCurrentThread() - allocated, sum);
    }

    private static void Assert(bool value) {
        if (!value)
            throw new Exception("Owned reference assertion failed.");
    }

    private static void Reject(Action action) => Expect<ArgumentException>(action);

    private static void Expect<T>(Action action) where T : Exception {
        try {
            action();
        } catch (T) {
            return;
        }

        throw new Exception($"Expected {typeof(T).Name}.");
    }
}
