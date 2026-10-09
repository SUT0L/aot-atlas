using Atlas;

internal static class RuntimeTypeIndexChecks {
    internal static void Run() {
        // These distinct argument pairs collide under the runtime lookup hash.
        // Matching must still compare the full ordered identity vector.
        ulong[] leaves = [0x140001000, 0x140001040, 0x140001080, 0x78001400136C0];
        const ulong definition = 0x140002000;

        var tables = new MethodTables(16);
        var builder = new SignatureBuilder();
        var maps = new ReflectionMaps();

        foreach (ulong leaf in leaves)
            Add(new MethodTable { Address = leaf, Flags = 0x14U << 26, BaseSize = 24 });

        Add(new MethodTable {
            Address = definition,
            Flags = (0x14U << 26) | (3U << 16),
            BaseSize = 24,
            GenericArity = 2
        });
        int named = Node(new SignatureNode { Kind = SignatureKind.Named, Name = "Pair" });
        maps.Types.Add(new TypeMapEntry { MethodTable = definition, Signature = named });

        int variable = Node(new SignatureNode { Kind = SignatureKind.MethodVariable });
        int variable2 = Node(new SignatureNode { Kind = SignatureKind.MethodVariable, Value = 1 });
        int ownerVariable = Node(new SignatureNode { Kind = SignatureKind.TypeVariable });
        int element = Node(new SignatureNode { Kind = SignatureKind.RuntimeType, TypeAddress = leaves[0] });

        int edge = builder.Edges.Length;
        builder.AddEdge(variable);
        builder.AddEdge(variable2);
        int pair = Node(new SignatureNode {
            Kind = SignatureKind.Instantiation,
            Element = named,
            Arguments = new(edge, 2)
        });
        int array = Node(new SignatureNode { Kind = SignatureKind.SzArray, Element = element });
        int pointer = Node(new SignatureNode { Kind = SignatureKind.Pointer, Element = element });
        int array3 = Node(new SignatureNode { Kind = SignatureKind.Array, Element = element, Value = 3 });
        int array4 = Node(new SignatureNode { Kind = SignatureKind.Array, Element = element, Value = 4 });

        for (int i = 0; i < 2; ++i) {
            Add(new MethodTable {
                Address = definition + (uint)(i + 1) * 64,
                Flags = (0x14U << 26) | 0x02000000U,
                BaseSize = 24,
                GenericDefinition = definition,
                Arguments = new(tables.Pointers.Count, 2)
            });
            tables.Pointers.Add(leaves[i * 2]);
            tables.Pointers.Add(leaves[i * 2 + 1]);
        }

        // Two SzArrays of one element make that shape ambiguous, independently
        // of the uniquely resolvable pointer and rank-three array.
        AddShape(0x140003000, 0x18, 24);
        AddShape(0x140003040, 0x18, 24);
        AddShape(0x140003080, 0x1A, 24);
        AddShape(0x1400030C0, 0x17, 48);

        var signatures = builder.Publish();
        var bindings = new TypeBindings(tables, maps, signatures);

        Check(bindings);

        // Query-local substitutions bypass persistent caches, so source changes
        // cannot be hidden by a previously cached successful answer.
        tables.Index.Clear();
        tables.Types[0] = new MethodTable { Address = 0xDEADBEEF, Flags = 0x14U << 26, BaseSize = 24 };
        tables.Types[5] = new MethodTable { Address = definition + 64, GenericDefinition = 0xFEED };
        tables.Pointers[0] = leaves[3];
        tables.Pointers[1] = leaves[2];
        tables.Types.Clear();
        tables.Pointers.Clear();

        Check(bindings);

        // A fresh snapshot must also preserve duplicate generic identities as
        // ambiguity rather than choosing the first hash bucket candidate.
        var duplicates = new MethodTables(4);
        AddDuplicate(leaves[0], 0, default);
        AddDuplicate(definition, 3U << 16, default);

        for (int i = 0; i < 2; ++i) {
            AddDuplicate(definition + (uint)(i + 1) * 64, 0x02000000U, new(duplicates.Pointers.Count, 2));
            duplicates.Pointers.Add(leaves[0]);
            duplicates.Pointers.Add(leaves[0]);
        }

        var duplicateBindings = new TypeBindings(duplicates, maps, signatures);
        ulong[] same = [leaves[0], leaves[0]];

        Assert(duplicateBindings.Resolve(pair, 0, same) == 0);

        maps.Types.Clear();
        int wrapper = builder.AddNode(new SignatureNode { Kind = SignatureKind.Modified, Element = pair });
        var later = builder.Publish();
        var clone = typeof(TypeBindings).GetMethod("WithSignatures",
            System.Reflection.BindingFlags.Instance | System.Reflection.BindingFlags.NonPublic)!;

        var rebound = (TypeBindings)clone.Invoke(bindings, [later])!;
        Assert(ReferenceEquals(rebound.Signatures, later));
        Check(rebound);
        Assert(rebound.Resolve(wrapper, 0, leaves.AsSpan(0, 2)) == 6);

        bool rejected = false;

        try {
            clone.Invoke(bindings, [new SignatureBuilder().Publish()]);
        } catch (System.Reflection.TargetInvocationException error) when (error.InnerException is ArgumentException) {
            rejected = true;
        }

        Assert(rejected);

        Console.WriteLine("Runtime identity ownership: hash collisions, duplicate shapes, ranked arrays and source destruction preserve binding answers.");

        void Check(TypeBindings query) {
            Assert(query.Resolve(pair, 0, leaves.AsSpan(0, 2)) == 6);
            Assert(query.Resolve(pair, 0, leaves.AsSpan(2, 2)) == 7);

            ulong[] reversed = [leaves[1], leaves[0]];
            Assert(query.Resolve(pair, 0, reversed) == 0);

            Assert(query.Resolve(ownerVariable, 6, leaves.AsSpan(0, 2)) == 1);
            Assert(query.Resolve(ownerVariable, 7, leaves.AsSpan(0, 2)) == 3);
            Assert(query.Resolve(element, 0, leaves.AsSpan(0, 2)) == 1);
            Assert(query.Resolve(array, 0, leaves.AsSpan(0, 2)) == 0);
            Assert(query.Resolve(pointer, 0, leaves.AsSpan(0, 2)) == 10);
            Assert(query.Resolve(array3, 0, leaves.AsSpan(0, 2)) == 11);
            Assert(query.Resolve(array4, 0, leaves.AsSpan(0, 2)) == 0);
        }

        int Node(SignatureNode node) => builder.AddNode(node);

        void Add(MethodTable type) {
            tables.Index.Add(type.Address, tables.Types.Count);
            tables.Types.Add(type);
        }

        void AddShape(ulong address, int kind, uint size) => Add(new MethodTable {
            Address = address,
            Flags = ((uint)kind << 26) | (2U << 16),
            BaseSize = size,
            RelatedType = leaves[0]
        });

        void AddDuplicate(ulong address, uint flags, IndexRange arguments) {
            duplicates.Index.Add(address, duplicates.Types.Count);
            duplicates.Types.Add(new MethodTable {
                Address = address,
                Flags = (0x14U << 26) | flags,
                BaseSize = 24,
                GenericDefinition = definition,
                Arguments = arguments
            });
        }
    }

    private static void Assert(bool condition) {
        if (!condition)
            throw new Exception("Runtime identity ownership check failed.");
    }
}
