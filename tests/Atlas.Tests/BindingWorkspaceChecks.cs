using Atlas;

internal static class BindingWorkspaceChecks {
    internal static void Run() {
        int queries = 0;

        foreach (int depth in new[] { 2, 4, 8, 16, 32, 64 }) {
            foreach (bool deepestFirst in new[] { false, true }) {
                foreach (SignatureKind variable in new[] {
                    SignatureKind.RuntimeType, SignatureKind.TypeVariable, SignatureKind.MethodVariable
                }) {
                    var fixture = new Fixture(depth, deepestFirst, variable);
                    var graph = fixture.Builder.Publish();
                    var cold = new TypeBindings(fixture.Tables, fixture.Maps, graph);

                    Check(cold, fixture.Root, 0);
                    Check(cold, fixture.Root, 1);

                    var warm = new TypeBindings(fixture.Tables, fixture.Maps, graph);

                    for (int level = 0; level < depth; ++level) {
                        for (int context = 0; context < 2; ++context) {
                            Check(warm, fixture.Compositions[level], context, level);
                        }
                    }

                    Check(warm, fixture.Root, 0);
                    Check(warm, fixture.Root, 1);

                    for (int repeat = 0; repeat < 8; ++repeat)
                        Check(cold, fixture.Root, repeat & 1);

                    if (variable == SignatureKind.MethodVariable) {
                        Assert(cold.Resolve(fixture.Root) == 0, "Incomplete method context must remain unresolved.");
                        Check(cold, fixture.Root, 0);
                        Check(cold, fixture.Root, 1);
                    } else if (variable == SignatureKind.TypeVariable) {
                        Assert(cold.Resolve(fixture.Root) == 0, "Missing owner must remain unresolved.");
                        Check(cold, fixture.Root, 0);
                        Check(cold, fixture.Root, 1);
                    }

                    int secondVariable = fixture.Builder.AddNode(new() {
                        Kind = SignatureKind.MethodVariable,
                        Value = 1
                    });
                    int edge = fixture.Builder.Edges.Length;
                    fixture.Builder.AddEdge(fixture.Root);
                    fixture.Builder.AddEdge(secondVariable);
                    int failing = fixture.Builder.AddNode(new() {
                        Kind = SignatureKind.Instantiation,
                        Element = fixture.Definitions[1],
                        Arguments = new(edge, 2)
                    });
                    int wrapper = fixture.Builder.AddNode(new() {
                        Kind = SignatureKind.Modified,
                        Element = fixture.Root
                    });

                    var expanded = new TypeBindings(fixture.Tables, fixture.Maps, fixture.Builder.Publish());
                    ulong[] failedArguments = [fixture.Leaves[0], ulong.MaxValue];
                    bool rejected = false;

                    try {
                        expanded.Resolve(failing, fixture.Owner(0), failedArguments);
                    } catch (KeyNotFoundException) {
                        rejected = true;
                    }

                    Assert(rejected, "Unknown method argument must reject the query after the first child resolves.");
                    Check(expanded, wrapper, 1);
                    Check(expanded, fixture.Root, 0);
                    Check(expanded, fixture.Root, 1);

                    // Growth and query caches are warm. Borrowed argument values and
                    // owner values alternate without requiring per-query storage.
                    ulong[] borrowed = [fixture.Leaves[0]];
                    expanded.Resolve(fixture.Root, fixture.Owner(0), fixture.Arguments(0));
                    expanded.Resolve(fixture.Root, fixture.Owner(1), fixture.Arguments(1));

                    for (int repeat = 0; repeat < 64; ++repeat) {
                        int context = repeat & 1;
                        borrowed[0] = fixture.Leaves[context];
                        ReadOnlySpan<ulong> arguments = variable == SignatureKind.MethodVariable ? borrowed : [];

                        expanded.Resolve(fixture.Root, fixture.Owner(context), arguments);
                    }

                    bool correct = true;
                    long allocated;

                    using (var measurement = new AllocationMeasurement()) {
                        for (int repeat = 0; repeat < 32; ++repeat) {
                            int context = repeat & 1;
                            borrowed[0] = fixture.Leaves[context];
                            ReadOnlySpan<ulong> arguments = variable == SignatureKind.MethodVariable ? borrowed : [];

                            correct &= expanded.Resolve(fixture.Root, fixture.Owner(context), arguments)
                                == fixture.Expected(context);
                        }

                        allocated = measurement.AllocatedBytes;
                    }

                    Assert(correct, "A warmed query reused another context's binding.");
                    Assert(allocated == 0,
                        $"Warm binding queries allocated {allocated} bytes at depth {depth}, deepestFirst {deepestFirst}, kind {variable}.");

                    void Check(TypeBindings bindings, int signature, int context, int level = -1) {
                        ++queries;

                        Assert(bindings.Resolve(signature, fixture.Owner(context), fixture.Arguments(context))
                            == fixture.Expected(context, level),
                            $"Shared-range answer differs at depth {depth}, deepestFirst {deepestFirst}, kind {variable}, level {level}, context {context}.");
                    }
                }
            }
        }

        Console.WriteLine($"Binding workspace: {queries} independently constructed shared-range answers preserve cold/warm order, owner/method isolation, failed-query recovery and allocation-free warm queries.");
    }

    private sealed class Fixture {
        internal readonly MethodTables Tables = new(256);
        internal readonly ReflectionMaps Maps = new();
        internal readonly SignatureBuilder Builder = new();

        internal readonly ulong[] Leaves = [0x140001000, 0x140001040];
        internal readonly int[] Compositions;
        internal readonly int[] Definitions;

        private readonly int[][] bindings;
        private readonly ulong[][] arguments;
        private readonly SignatureKind variable;

        internal int Root => Compositions[^1];

        internal Fixture(int depth, bool deepestFirst, SignatureKind variable) {
            this.variable = variable;
            Compositions = new int[depth];
            Definitions = new int[depth];
            bindings = new int[depth][];
            arguments = [[Leaves[0]], [Leaves[1]]];

            foreach (ulong leaf in Leaves)
                Add(new() { Address = leaf, Flags = 0x14U << 26, BaseSize = 24 });

            int leafNode = Builder.AddNode(new() {
                Kind = variable,
                TypeAddress = variable == SignatureKind.RuntimeType ? Leaves[0] : 0
            });
            Builder.ReserveEdges(depth);
            Builder.SetEdge(deepestFirst ? depth - 1 : 0, leafNode);

            var vectors = new[] { new List<ulong> { Leaves[0] }, new List<ulong> { Leaves[1] } };

            for (int level = 0; level < depth; ++level) {
                int arity = level + 1;
                ulong definition = 0x140010000UL + (uint)arity * 64;

                Add(new() {
                    Address = definition,
                    Flags = (0x14U << 26) | (3U << 16),
                    BaseSize = (uint)arity,
                    GenericArity = (ushort)arity
                });
                Definitions[level] = Builder.AddNode(new() { Kind = SignatureKind.Named, Name = $"G{arity}" });
                Maps.Types.Add(new() { MethodTable = definition, Signature = Definitions[level] });

                Compositions[level] = Builder.AddNode(new() {
                    Kind = SignatureKind.Instantiation,
                    Element = Definitions[level],
                    Arguments = new(deepestFirst ? depth - arity : 0, arity)
                });
                if (level + 1 < depth)
                    Builder.SetEdge(deepestFirst ? depth - arity - 1 : arity, Compositions[level]);

                bindings[level] = new int[2];

                for (int context = 0; context < 2; ++context) {
                    ulong address = 0x140020000UL + (uint)arity * 128 + (uint)context * 64;
                    var range = new IndexRange(Tables.Pointers.Count, arity);
                    Tables.Pointers.AddRange(vectors[context]);

                    bindings[level][context] = Add(new() {
                        Address = address,
                        Flags = (0x14U << 26) | 0x02000000U,
                        BaseSize = 24,
                        GenericArity = (ushort)arity,
                        GenericDefinition = definition,
                        Arguments = range
                    });

                    if (deepestFirst)
                        vectors[context].Insert(0, address);
                    else
                        vectors[context].Add(address);
                }
            }
        }

        internal int Owner(int context) => variable == SignatureKind.TypeVariable ? bindings[0][context] : 0;

        internal ReadOnlySpan<ulong> Arguments(int context) =>
            variable == SignatureKind.MethodVariable ? arguments[context] : [];

        internal int Expected(int context, int level = -1) =>
            bindings[level < 0 ? bindings.Length - 1 : level][variable == SignatureKind.RuntimeType ? 0 : context];

        private int Add(MethodTable type) {
            int index = Tables.Types.Count;
            Tables.Index.Add(type.Address, index);
            Tables.Types.Add(type);

            return index + 1;
        }
    }

    private static void Assert(bool condition, string message) {
        if (!condition)
            throw new Exception(message);
    }
}
