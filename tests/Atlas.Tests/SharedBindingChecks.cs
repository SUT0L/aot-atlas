using Atlas;
using System.Reflection;

internal static class SharedBindingChecks {
    internal static void Run() {
        const int depth = 64;

        var tables = new MethodTables();
        var maps = new ReflectionMaps();
        var signatures = new SignatureBuilder();

        ulong[] leaves = [0x140001000, 0x140001040];
        const ulong definition = 0x140002000;

        foreach (ulong leaf in leaves)
            Add(new MethodTable { Address = leaf, Flags = 0x14U << 26, BaseSize = 24 });

        Add(new MethodTable {
            Address = definition,
            Flags = (0x14U << 26) | (3U << 16),
            BaseSize = 24,
            GenericArity = 2
        });
        signatures.AddNode(new SignatureNode { Kind = SignatureKind.Named, Name = "Pair" });
        maps.Types.Add(new TypeMapEntry { MethodTable = definition, Signature = 1 });
        signatures.AddNode(new SignatureNode { Kind = SignatureKind.MethodVariable, Value = 0 });

        int root = 2;
        ulong[] previous = (ulong[])leaves.Clone();

        for (int level = 0; level < depth; ++level) {
            int edge = signatures.Edges.Length;
            signatures.AddEdge(root);
            signatures.AddEdge(root);
            signatures.AddNode(new SignatureNode {
                Kind = SignatureKind.Instantiation,
                Element = 1,
                Arguments = new(edge, 2)
            });
            root = signatures.Nodes.Length - 1;

            for (int context = 0; context < leaves.Length; ++context) {
                ulong address = definition + (uint)(level * 2 + context + 1) * 64;
                Add(new MethodTable {
                    Address = address,
                    Flags = (0x14U << 26) | 0x02000000U,
                    BaseSize = 24,
                    GenericDefinition = definition,
                    Arguments = new(tables.Pointers.Count, 2)
                });
                tables.Pointers.Add(previous[context]);
                tables.Pointers.Add(previous[context]);
                previous[context] = address;
            }
        }

        signatures.AddNode(new SignatureNode { Kind = SignatureKind.Modified, Element = root });
        int modified = signatures.Nodes.Length - 1;
        signatures.AddNode(new SignatureNode { Kind = SignatureKind.TypeVariable, Value = 0 });
        int ownerVariable = signatures.Nodes.Length - 1;
        signatures.AddNode(new SignatureNode { Kind = SignatureKind.Modified, Element = ownerVariable });
        int ownerModified = signatures.Nodes.Length - 1;
        signatures.AddNode(new SignatureNode { Kind = SignatureKind.MethodVariable, Value = 1 });
        int secondVariable = signatures.Nodes.Length - 1;
        signatures.AddNode(new SignatureNode { Kind = SignatureKind.Modified, Element = secondVariable });
        int secondModified = signatures.Nodes.Length - 1;

        int failingEdge = signatures.Edges.Length;
        signatures.AddEdge(modified);
        signatures.AddEdge(secondModified);
        signatures.AddNode(new SignatureNode {
            Kind = SignatureKind.Instantiation,
            Element = 1,
            Arguments = new(failingEdge, 2)
        });
        int failingRoot = signatures.Nodes.Length - 1;

        var bindings = new TypeBindings(tables, maps, signatures.Publish());
        int[] expected = previous.Select(address => tables.Index[address] + 1).ToArray();
        Span<ulong> arguments = stackalloc ulong[2];

        for (int i = 0; i < 1000; ++i) {
            int context = i & 1;
            arguments[0] = leaves[context];
            arguments[1] = leaves[context ^ 1];

            Assert(bindings.Resolve(root, 0, arguments) == expected[context]);
            Assert(bindings.Resolve(modified, 0, arguments) == expected[context]);
            Assert(bindings.Resolve(root) == 0);
            Assert(bindings.Resolve(secondModified, 0, arguments[..1]) == 0);
            Assert(bindings.Resolve(secondModified, 0, arguments) == (context ^ 1) + 1);

            int owner = 4 + context;
            Assert(bindings.Resolve(ownerModified, owner, arguments) == context + 1);
        }

        int edgeCount = signatures.Edges.Length;
        signatures.AddNode(new SignatureNode { Kind = SignatureKind.Modified, Element = root });
        int lateModified = signatures.Nodes.Length - 1;
        bindings = new TypeBindings(tables, maps, signatures.Publish());
        arguments[0] = leaves[0];

        Assert(bindings.Resolve(lateModified, 0, arguments) == expected[0]);

        signatures.AddNode(new SignatureNode { Kind = SignatureKind.Modified, Element = lateModified });
        arguments[0] = leaves[1];
        bindings = new TypeBindings(tables, maps, signatures.Publish());

        Assert(bindings.Resolve(signatures.Nodes.Length - 1, 0, arguments) == expected[1]);
        Assert(signatures.Edges.Length == edgeCount);

        // Reusing a generation after wrap must retire both successful and zero results.
        arguments[0] = leaves[0];
        var generation = typeof(TypeBindings).GetField("methodGeneration", BindingFlags.Instance | BindingFlags.NonPublic)!;
        Assert(bindings.Resolve(modified, 0, arguments) == expected[0]);

        generation.SetValue(bindings, uint.MaxValue);
        arguments[0] = leaves[1];

        Assert(bindings.Resolve(modified, 0, arguments) == expected[1]);
        Assert(bindings.Resolve(secondModified, 0, arguments[..1]) == 0);

        generation.SetValue(bindings, uint.MaxValue);
        arguments[1] = leaves[0];

        Assert(bindings.Resolve(secondModified, 0, arguments) == 1);

        arguments[0] = leaves[0];
        arguments[1] = ulong.MaxValue;

        try {
            bindings.Resolve(failingRoot, 0, arguments);
            throw new Exception("Unknown runtime argument should fail.");
        } catch (KeyNotFoundException) {
        }

        arguments[0] = leaves[1];
        arguments[1] = leaves[0];

        Assert(bindings.Resolve(modified, 0, arguments) == expected[1]);

        long allocated;

        using (var measurement = new AllocationMeasurement()) {
            for (int i = 0; i < 1000; ++i) {
                arguments[0] = leaves[i & 1];
                Assert(bindings.Resolve(root, 0, arguments) == expected[i & 1]);
            }

            allocated = measurement.AllocatedBytes;
        }

        Assert(allocated == 0);

        Console.WriteLine("Shared bindings: depth-64 DAGs, alternating borrowed arguments/owners, incomplete arguments, failed queries, new wrapper publications and generation wrap preserve exact identities without warm allocations.");

        void Add(MethodTable type) {
            tables.Index.Add(type.Address, tables.Types.Count);
            tables.Types.Add(type);
        }
    }

    private static void Assert(bool condition, [System.Runtime.CompilerServices.CallerLineNumber] int line = 0) {
        if (!condition)
            throw new Exception($"Shared binding identity or lifetime differs at line {line}.");
    }
}
