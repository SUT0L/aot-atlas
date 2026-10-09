using Atlas;
using System.Diagnostics.CodeAnalysis;
using System.Reflection;

internal static class SignatureComparisonChecks {
    [DynamicallyAccessedMembers(
        DynamicallyAccessedMemberTypes.PublicConstructors | DynamicallyAccessedMemberTypes.NonPublicMethods)]
    private static readonly Type comparisonType = Type.GetType("Atlas.SignatureComparison, Atlas", throwOnError: true)!;

    internal static void Run() {
        IdentityAndConventions();
        SharedGraphsAndFailures();
        CachedNativeDepth();

        Console.WriteLine("Signature comparison: scoped identities, conventions, bounds/modifiers/varargs, shared DAGs, cached native depth20000, late mismatches and failed-query replay agree without warm allocations.");
    }

    private static void IdentityAndConventions() {
        const ulong leaf = 0x140001000;
        var tables = new MethodTables(0);
        tables.Index.Add(leaf, 0);
        tables.Types.Add(new() { Address = leaf, Flags = 0x10U << 26, BaseSize = 24 });

        var builder = new SignatureBuilder();
        var maps = new ReflectionMaps();

        int named = builder.AddNode(new() { Kind = SignatureKind.Named, Name = "Same", MetadataScope = 1 });
        int runtime = builder.AddNode(new() { Kind = SignatureKind.RuntimeType, TypeAddress = leaf });
        int unresolved = builder.AddNode(new() { Kind = SignatureKind.Named, Name = "Same", MetadataScope = 2 });
        int another = builder.AddNode(new() { Kind = SignatureKind.Named, Name = "Same", MetadataScope = 2 });

        int unknown = builder.AddNode(default);
        int otherUnknown = builder.AddNode(default);

        int variable = builder.AddNode(new() { Kind = SignatureKind.TypeVariable, Value = 0 });
        int otherVariable = builder.AddNode(new() { Kind = SignatureKind.TypeVariable, Value = 1 });
        int methodVariable = builder.AddNode(new() { Kind = SignatureKind.MethodVariable, Value = 0 });
        maps.Types.Add(new() { Signature = named, MethodTable = leaf });

        int array = builder.AddNode(new() {
            Kind = SignatureKind.Array,
            Element = variable,
            Value = 2,
            Sizes = Edges(3),
            LowerBounds = Edges(-1)
        });
        int otherArray = builder.AddNode(new() {
            Kind = SignatureKind.Array,
            Element = variable,
            Value = 2,
            Sizes = Edges(4),
            LowerBounds = Edges(-1)
        });
        int otherBounds = builder.AddNode(new() {
            Kind = SignatureKind.Array,
            Element = variable,
            Value = 2,
            Sizes = Edges(3),
            LowerBounds = Edges(0)
        });
        int otherRank = builder.AddNode(new() {
            Kind = SignatureKind.Array,
            Element = variable,
            Value = 1,
            Sizes = Edges(3),
            LowerBounds = Edges(-1)
        });

        int modifier = builder.AddNode(new() {
            Kind = SignatureKind.Modified, Element = array, Value = named
        });
        int sameModifier = builder.AddNode(new() {
            Kind = SignatureKind.Modified, Element = array, Value = runtime
        });
        int optionalModifier = builder.AddNode(new() {
            Kind = SignatureKind.Modified, Element = array, Value = runtime, Optional = true
        });
        int otherModifier = builder.AddNode(new() {
            Kind = SignatureKind.Modified, Element = array, Value = unresolved
        });

        int pointer = builder.AddNode(new() {
            Kind = SignatureKind.FunctionPointer, Element = variable, Varargs = Edges(variable)
        });
        int samePointer = builder.AddNode(new() {
            Kind = SignatureKind.FunctionPointer, Element = variable, Varargs = Edges(variable)
        });
        int otherPointer = builder.AddNode(new() {
            Kind = SignatureKind.FunctionPointer, Element = variable, Varargs = Edges(otherVariable)
        });
        int nativePointer = builder.AddNode(new() {
            Kind = SignatureKind.FunctionPointer,
            Element = variable,
            Varargs = Edges(variable),
            NativeConvention = true
        });
        var expected = new List<(int Left, int Right, bool Equal)>();

        Check(named, runtime, true);
        Check(named, unresolved, false);
        Check(unresolved, another, false);
        Check(unresolved, unresolved, true);
        Check(unknown, otherUnknown, false);
        Check(unknown, unknown, true);
        Check(0, 0, false);
        Check(variable, otherVariable, false);
        Check(variable, methodVariable, false);
        Check(array, otherArray, false);
        Check(array, otherBounds, false);
        Check(array, otherRank, false);
        Check(modifier, sameModifier, true);
        Check(modifier, optionalModifier, false);
        Check(modifier, otherModifier, false);
        Check(pointer, samePointer, true);
        Check(pointer, otherPointer, false);
        Check(pointer, nativePointer, false);

        foreach (var kind in new[] { SignatureKind.SzArray, SignatureKind.ByReference, SignatureKind.Pointer }) {
            int first = builder.AddNode(new() { Kind = kind, Element = variable });
            int same = builder.AddNode(new() { Kind = kind, Element = variable });
            int different = builder.AddNode(new() { Kind = kind, Element = otherVariable });
            Check(first, same, true);
            Check(first, different, false);
        }

        int plain = Method(variable);
        int genericFlag = Method(variable, convention: 0x10);
        int staticNative = Method(variable, convention: 2, native: true);
        int instance = Method(variable, convention: 0x20);
        int instanceNative = Method(variable, native: true);
        int unsupportedNative = Method(variable, convention: 4, native: true);
        int generic = Method(variable, arity: 1);
        int parameters = builder.AddMethod(new() { ReturnType = variable, Parameters = Edges(variable) });
        int otherParameters = builder.AddMethod(new() { ReturnType = variable, Parameters = Edges(otherVariable) });
        int varargs = builder.AddMethod(new() { ReturnType = variable, Varargs = Edges(variable) });
        expected.AddRange([
            (plain, genericFlag, true), (plain, staticNative, true), (instance, instanceNative, true),
            (plain, instance, false), (plain, unsupportedNative, false), (unsupportedNative, unsupportedNative, false),
            (plain, generic, false), (plain, parameters, false), (parameters, otherParameters, false),
            (varargs, varargs, false), (0, plain, false)
        ]);

        var graph = builder.Publish();
        var equal = Comparison(graph, new(tables, maps, graph));

        foreach (var item in expected) {
            Assert(equal(item.Left, item.Right) == item.Equal, "A signature identity or convention differs.");
            Assert(equal(item.Right, item.Left) == item.Equal, "Comparison lost symmetry.");
        }

        void Check(int left, int right, bool match) => expected.Add((Method(left), Method(right), match));

        int Method(int root, uint convention = 0, bool native = false, int arity = 0) => builder.AddMethod(new() {
            ReturnType = root,
            CallingConvention = convention,
            NativeConvention = native,
            GenericParameterCount = arity
        });

        IndexRange Edges(params int[] values) {
            int start = builder.Edges.Length;

            foreach (int value in values)
                builder.AddEdge(value);

            return new(start, values.Length);
        }
    }

    private static void SharedGraphsAndFailures() {
        var builder = new SignatureBuilder();
        int definition = builder.AddNode(new() { Kind = SignatureKind.Named, Name = "Pair`2" });
        int a = builder.AddNode(new() { Kind = SignatureKind.TypeVariable });
        int b = builder.AddNode(new() { Kind = SignatureKind.TypeVariable });
        int different = builder.AddNode(new() { Kind = SignatureKind.TypeVariable, Value = 1 });
        int badRuntime = builder.AddNode(new() { Kind = SignatureKind.RuntimeType, TypeAddress = ulong.MaxValue });
        int otherRuntime = builder.AddNode(new() { Kind = SignatureKind.RuntimeType, TypeAddress = ulong.MaxValue - 1 });
        int leftLeaf = a;
        int rightLeaf = b;
        int leafLeft = Method(leftLeaf);
        int leafRight = Method(rightLeaf);

        for (int i = 0; i < 64; ++i) {
            a = Pair(a, a);
            b = Pair(b, b);
            different = Pair(different, different);
        }

        int good = Method(a);
        int same = Method(b);
        int unequal = Method(Pair(a, different));
        int late = Method(Pair(a, b));
        int runtimeFailure = Method(Pair(badRuntime, a));
        int runtimeOther = Method(Pair(otherRuntime, b));
        int cycleA = builder.AddNode(new() { Kind = SignatureKind.Pointer });
        int cycleB = builder.AddNode(new() { Kind = SignatureKind.Pointer });
        builder.SetNode(cycleA, new() { Kind = SignatureKind.Pointer, Element = cycleA });
        builder.SetNode(cycleB, new() { Kind = SignatureKind.Pointer, Element = cycleB });
        int cycleLeft = Method(cycleA);
        int cycleRight = Method(cycleB);
        var graph = builder.Publish();
        var equal = Comparison(graph, new(new MethodTables(0), new ReflectionMaps(), graph));

        for (int repeat = 0; repeat < 3; ++repeat) {
            Assert(!equal(late, unequal), "A late differing DAG leaf became equal.");
            Assert(!equal(unequal, late), "A failed pair poisoned reversed comparison.");
            Assert(equal(good, same), "A failed parent poisoned its completed child.");
            Assert(equal(leafLeft, leafRight), "A failed parent poisoned a disjoint leaf.");
            Expect<InvalidDataException>(() => equal(cycleLeft, cycleRight));
            Assert(equal(good, same), "A cyclic query poisoned a healthy comparison.");
            Expect<KeyNotFoundException>(() => equal(runtimeFailure, runtimeOther));
            Assert(equal(good, same), "A failed binding query poisoned a healthy comparison.");
        }

        long allocated;
        using (var measurement = new AllocationMeasurement()) {
            bool exact = true;

            for (int i = 0; i < 1000; ++i)
                exact &= equal(good, same) && !equal(late, unequal) && !equal(unequal, late);

            allocated = measurement.AllocatedBytes;
            Assert(exact, "A warm DAG comparison changed its answer.");
        }

        Assert(allocated == 0, "A warm DAG comparison allocated storage.");

        builder.SetNode(rightLeaf, new() { Kind = SignatureKind.TypeVariable, Value = 1 });
        var changed = builder.Publish();

        Assert(!Comparison(changed, new(new MethodTables(0), new ReflectionMaps(), changed))(good, same),
            "A changed publication reused old equality evidence.");
        Assert(equal(good, same), "A new publication changed a previous operation's graph.");
        builder.SetNode(rightLeaf, new() { Kind = SignatureKind.TypeVariable });
        var restored = builder.Publish();

        Assert(Comparison(restored, new(new MethodTables(0), new ReflectionMaps(), restored))(good, same),
            "Restoring a published leaf did not restore equality.");

        int Pair(int first, int second) {
            int start = builder.Edges.Length;
            builder.AddEdge(first);
            builder.AddEdge(second);

            return builder.AddNode(new() {
                Kind = SignatureKind.Instantiation,
                Element = definition,
                Arguments = new(start, 2)
            });
        }

        int Method(int root) => builder.AddMethod(new() { ReturnType = root });
    }

    private static void CachedNativeDepth() {
        const int depth = 20000;
        const ulong leaf = 0x140001000;
        var builder = new SignatureBuilder();
        byte[] blob = new byte[depth * 2 + 1];
        blob[0] = 12;

        for (int i = 0; i < depth; ++i) {
            blob[1 + i * 2] = 100;
            blob[2 + i * 2] = (byte)(i == 0 ? 2 : 34);
        }

        int left = Read();
        int right = Read();
        int methodLeft = builder.AddMethod(new() { ReturnType = left });
        int methodRight = builder.AddMethod(new() { ReturnType = right });
        var tables = new MethodTables(0);
        tables.Index.Add(leaf, 0);
        tables.Types.Add(new() { Address = leaf, Flags = 0x10U << 26, BaseSize = 24 });
        var graph = builder.Publish();
        var equal = Comparison(graph, new(tables, new ReflectionMaps(), graph));

        Assert(equal(methodLeft, methodRight), "Cached native deep signature identities differ.");
        Assert(equal(methodRight, methodLeft), "Deep comparison lost symmetry.");

        int Read() {
            var layout = new NativeLayout(blob, [leaf], builder, takeOwnership: true);
            var reader = new NativeReader(blob);
            int root = layout.TypeSignature(ref reader);

            for (int i = 0; i < depth; ++i) {
                reader.Position = 1 + i * 2;
                root = layout.TypeSignature(ref reader);
            }

            return root;
        }
    }

    private static Func<int, int, bool> Comparison(Signatures graph, TypeBindings bindings) {
        object instance = Activator.CreateInstance(comparisonType, graph, bindings)!;
        return comparisonType.GetMethod("EqualMethod", BindingFlags.Instance | BindingFlags.NonPublic)!
            .CreateDelegate<Func<int, int, bool>>(instance);
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
