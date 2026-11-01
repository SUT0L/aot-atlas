using Atlas;

internal static class IterativeBindingChecks {
    internal static void Run() {
        DeepCachedNativeLayout();
        DeepSubstitutions();

        Console.WriteLine("Iterative bindings: cached NativeLayout depth20000, substituted modifier depth20000 and failed-query replay preserve exact identities without stack recursion.");
    }

    private static void DeepCachedNativeLayout() {
        const int depth = 20000;
        const ulong leaf = 0x140001000;

        var tables = Leaves(leaf);
        var builder = new SignatureBuilder();

        byte[] blob = new byte[depth * 2 + 1];
        blob[0] = 12; // External reference0.

        for (int i = 0; i < depth; ++i) {
            blob[1 + i * 2] = 100; // Pointer modifier.
            blob[2 + i * 2] = (byte)(i == 0 ? 2 : 34); // Lookback to the previous root.
        }

        var layout = new NativeLayout(blob, [leaf], builder, takeOwnership: true);
        var reader = new NativeReader(blob);
        int root = layout.TypeSignature(ref reader);

        for (int i = 0; i < depth; ++i) {
            reader.Position = 1 + i * 2;
            root = layout.TypeSignature(ref reader);

            Assert(reader.Position == 3 + i * 2, "Cached lookback root advanced incorrectly.");
        }

        var graph = builder.Publish();
        Assert(graph.Nodes.Length == depth + 2 && graph.RenderType(root) == $"sig_ref_{root}",
            "The deep native graph lost its identity.");

        var bindings = new TypeBindings(tables, new ReflectionMaps(), graph);

        // No pointer EEType is present. Its absence is a normal unresolved answer,
        // even though cached producer references created a deep dependency graph.
        Assert(bindings.Resolve(root) == 0, "Unrepresented pointer identity became a runtime binding.");
        Assert(bindings.Resolve(root, 0, new ulong[] { leaf }) == 0,
            "Borrowed context changed a native type identity.");
        Assert(bindings.Resolve(1) == 1, "Deep unresolved native graph poisoned the leaf binding.");

        // Independently declared parameterized rows make every transition a
        // positive identity lookup, rather than testing only an early miss.
        ulong element = leaf;

        for (int i = 0; i < depth; ++i) {
            ulong address = leaf + (uint)(i + 1) * 64;
            tables.Index.Add(address, tables.Types.Count);
            tables.Types.Add(new() {
                Address = address,
                Flags = (0x1AU << 26) | (2U << 16),
                RelatedType = element
            });
            element = address;
        }

        var represented = new TypeBindings(tables, new ReflectionMaps(), graph);
        Assert(represented.Resolve(root) == depth + 1, "Deep native pointer chain lost its exact outer identity.");

        ulong[] borrowed = [leaf];
        Assert(represented.Resolve(root, 0, borrowed) == depth + 1,
            "Positive native graph failed with borrowed context.");
        Assert(bindings.Resolve(root, 0, borrowed) == 0,
            "Appending source rows changed a completed runtime snapshot.");

        Assert(represented.Resolve(root, 0, borrowed) == depth + 1,
            "Deep warm native graph changed identity.");
    }

    private static void DeepSubstitutions() {
        const int depth = 20000;
        ulong[] leaves = [0x140001000, 0x140001040];
        var tables = Leaves(leaves);

        foreach (var kind in new[] { SignatureKind.RuntimeType, SignatureKind.MethodVariable }) {
            var builder = new SignatureBuilder();
            int modifier = builder.AddNode(new() { Kind = SignatureKind.RuntimeType, TypeAddress = leaves[0] });
            int root = builder.AddNode(new() {
                Kind = kind,
                TypeAddress = kind == SignatureKind.RuntimeType ? leaves[0] : 0
            });

            for (int i = 0; i < depth; ++i)
                root = builder.AddNode(new() { Kind = SignatureKind.Modified, Element = root, Value = modifier });

            var bindings = new TypeBindings(tables, new ReflectionMaps(), builder.Publish());
            ulong[] borrowed = [leaves[0]];
            Assert(bindings.Resolve(root, 0, borrowed) == 1, "Deep initial substitution changed identity.");

            borrowed[0] = ulong.MaxValue;

            if (kind == SignatureKind.MethodVariable)
                Expect<KeyNotFoundException>(() => bindings.Resolve(root, 0, borrowed));
            else
                Assert(bindings.Resolve(root, 0, borrowed) == 1, "An unused method argument changed a closed signature.");

            borrowed[0] = leaves[1];
            Assert(bindings.Resolve(root, 0, borrowed) == (kind == SignatureKind.MethodVariable ? 2 : 1),
                "Deep failed substitution leaked another generation.");
            Assert(bindings.Resolve(root) == (kind == SignatureKind.MethodVariable ? 0 : 1),
                "Empty context reused a method substitution.");

            borrowed[0] = leaves[0];
            Assert(bindings.Resolve(root, 0, borrowed) == 1, "Context replay failed after a deep query.");
        }
    }

    private static MethodTables Leaves(params ulong[] addresses) {
        var tables = new MethodTables(addresses.Length);

        foreach (ulong address in addresses) {
            tables.Index.Add(address, tables.Types.Count);
            tables.Types.Add(new() { Address = address, Flags = 0x14U << 26, BaseSize = 24 });
        }

        return tables;
    }

    private static void Expect<T>(Action action) where T : Exception {
        try {
            action();
        } catch (T) {
            return;
        }

        throw new Exception($"Expected {typeof(T).Name}.");
    }

    private static void Assert(bool condition, string message) {
        if (!condition)
            throw new Exception(message);
    }
}
