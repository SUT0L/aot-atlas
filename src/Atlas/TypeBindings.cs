using System.Runtime.InteropServices;

namespace Atlas;

public sealed class TypeBindings {
    private readonly RuntimeTypeIndex runtime;
    private readonly Signatures signatures;
    public Signatures Signatures => signatures;

    private readonly int[] named;
    private ulong[] arguments = [];
    private readonly Dictionary<(int Signature, int Owner), int> resolved = new();

    private BindingFrame[] frames = [];

    private struct BindingFrame {
        internal int Signature;
        internal int Element;
        internal int Argument;
        internal int Start;
        internal bool Complete;
    }

    private bool[]? active;

    private readonly record struct QueryBinding(uint Generation, int Binding);
    private QueryBinding[]? methodResults;
    private uint methodGeneration;

    public static TypeBindings Create(RuntimeTypePublication tables, ReflectionMaps maps, Signatures signatures) {
        maps.RequireSignaturePublication(signatures);
        return new(new RuntimeTypeIndex(tables), maps, signatures);
    }

    internal TypeBindings(MethodTables tables, ReflectionMaps maps, Signatures signatures)
        : this(new RuntimeTypeIndex(tables), maps, signatures) {
    }

    internal TypeBindings(RuntimeTypeIndex runtime, ReflectionMaps maps, Signatures signatures) {
        maps.ValidateSignatureOrigin(signatures.Origin);

        this.runtime = runtime;
        this.signatures = signatures;
        named = new int[signatures.Nodes.Length];

        foreach (ref readonly var entry in CollectionsMarshal.AsSpan(maps.Types)) {
            int binding = runtime.Binding(entry.MethodTable);

            ref int slot = ref named[entry.Signature];
            slot = slot == 0 || slot == binding ? binding : -1;
        }
    }

    private TypeBindings(RuntimeTypeIndex runtime, ReadOnlySpan<int> named, Signatures graph) {
        this.runtime = runtime;
        signatures = graph;
        this.named = new int[graph.Nodes.Length];
        named.CopyTo(this.named);
    }

    internal TypeBindings WithSignatures(Signatures graph) {
        if (ReferenceEquals(graph, signatures))
            return this;

        if (!graph.SharesOrigin(signatures))
            throw new ArgumentException("Binding signatures must belong to the same graph namespace.", nameof(graph));

        if (!graph.Extends(signatures))
            throw new ArgumentException("Binding signatures must preserve the previously published graph.", nameof(graph));

        return new TypeBindings(runtime, named, graph);
    }

    public RuntimeTypeReference RuntimeType(ulong address) => new(runtime, runtime.Binding(address));

    public RuntimeTypeReference Resolve(
        SignatureType signature,
        RuntimeTypeReference owner = default,
        ReadOnlySpan<RuntimeTypeReference> methodArguments = default) {
        if (!ReferenceEquals(signature.Publication, signatures))
            throw new ArgumentException("The signature belongs to a different immutable publication.", nameof(signature));

        int ownerBinding = owner.For(runtime);

        if (methodArguments.IsEmpty)
            return new(runtime, Resolve(signature.Index, ownerBinding));

        return ResolveWithArguments(signature.Index, ownerBinding, methodArguments);
    }

    private RuntimeTypeReference ResolveWithArguments(
        int signature,
        int owner,
        ReadOnlySpan<RuntimeTypeReference> methodArguments) {
        Span<ulong> addresses = methodArguments.Length <= 256
            ? stackalloc ulong[methodArguments.Length]
            : new ulong[methodArguments.Length];

        for (int i = 0; i < methodArguments.Length; ++i) {
            methodArguments[i].For(runtime);
            addresses[i] = methodArguments[i].Address;
        }

        return new(runtime, Resolve(signature, owner, addresses));
    }

    // Dense indices are confined to the validated extraction operation.
    internal int Resolve(int signature, int owner = 0, ReadOnlySpan<ulong> methodArguments = default) {
        if (!methodArguments.IsEmpty) {
            methodGeneration = unchecked(methodGeneration + 1);

            if (methodGeneration == 0) {
                if (methodResults is not null)
                    Array.Clear(methodResults);

                methodGeneration = 1;
            }
        }

        if (TryResolve(signature, owner, methodArguments, out int binding))
            return binding;

        return ResolveGraph(signature, owner, methodArguments);
    }

    private bool TryResolve(
        int signature,
        int owner,
        ReadOnlySpan<ulong> methodArguments,
        out int binding) {
        ref readonly var node = ref signatures.Nodes[signature];

        if (node.TypeAddress != 0) {
            binding = runtime.Binding(node.TypeAddress);
            return true;
        }

        if (node.Kind == SignatureKind.Named) {
            binding = Math.Max(0, named[signature]);
            return true;
        }

        if (node.Kind == SignatureKind.MethodVariable) {
            binding = node.Value < methodArguments.Length
                ? runtime.Binding(methodArguments[node.Value])
                : 0;
            return true;
        }

        if (node.Kind == SignatureKind.TypeVariable) {
            binding = owner == 0 ? 0 : runtime.Argument(owner, node.Value);
            return true;
        }

        if (node.Kind is not (
            SignatureKind.Modified
            or SignatureKind.Instantiation
            or SignatureKind.Array
            or SignatureKind.SzArray
            or SignatureKind.Pointer
            or SignatureKind.ByReference)) {
            binding = 0;
            return true;
        }

        // Persistent results include the owner. Borrowed method arguments and the
        // owner remain constant throughout one root query's generation.
        bool present;

        if (methodArguments.IsEmpty) {
            present = resolved.TryGetValue((signature, owner), out binding);
        } else {
            methodResults ??= new QueryBinding[signatures.Nodes.Length];

            var cached = methodResults[signature];
            present = cached.Generation == methodGeneration;
            binding = cached.Binding;
        }

        return present;
    }

    private int ResolveGraph(int signature, int owner, ReadOnlySpan<ulong> methodArguments) {
        active ??= new bool[signatures.Nodes.Length];

        int depth = 0;
        int start = 0;
        int current = signature;

        try {
            while (true) {
                int value;

                while (!TryResolve(current, owner, methodArguments, out value)) {
                    if (active[current])
                        throw new InvalidDataException($"Cyclic runtime binding signature at sig_ref_{current}.");

                    if (depth == frames.Length)
                        Array.Resize(ref frames, checked(Math.Max(16, depth * 2)));

                    active[current] = true;
                    frames[depth++] = new() {
                        Signature = current,
                        Argument = -1,
                        Start = start,
                        Complete = true
                    };
                    current = signatures.Nodes[current].Element;
                }

                // A terminal child is folded into its parent. Completed parents
                // unwind without recursion; another argument resumes descent.
                while (depth != 0) {
                    ref var frame = ref frames[depth - 1];
                    ref readonly var node = ref signatures.Nodes[frame.Signature];

                    if (frame.Argument < 0) {
                        if (value != 0 && node.Kind == SignatureKind.Instantiation) {
                            frame.Element = value;
                            int end = checked(frame.Start + node.Arguments.Count);

                            if (arguments.Length < end)
                                Array.Resize(
                                    ref arguments,
                                    Math.Max(
                                        end,
                                        (int)Math.Min(
                                            Math.Max(16L, (long)arguments.Length * 2),
                                            Array.MaxLength)));

                            frame.Argument = 0;

                            if (node.Arguments.Count != 0) {
                                current = signatures.Edges[node.Arguments.Start];
                                start = end;
                                break;
                            }

                            value = runtime.Instantiation(runtime.Address(frame.Element), []);
                        } else if (value != 0 && node.Kind != SignatureKind.Modified) {
                            int kind = node.Kind switch {
                                SignatureKind.Array => 0x17,
                                SignatureKind.SzArray => 0x18,
                                SignatureKind.ByReference => 0x19,
                                _ => 0x1A
                            };
                            value = runtime.Parameterized(
                                kind,
                                kind == 0x17 ? node.Value : 0,
                                runtime.Address(value));
                        }
                    } else {
                        arguments[frame.Start + frame.Argument] = value == 0 ? 0 : runtime.Address(value);
                        frame.Complete &= value != 0;

                        if (++frame.Argument < node.Arguments.Count) {
                            current = signatures.Edges[node.Arguments.Start + frame.Argument];
                            start = frame.Start + node.Arguments.Count;
                            break;
                        }

                        value = frame.Complete
                            ? runtime.Instantiation(
                                runtime.Address(frame.Element),
                                arguments.AsSpan(frame.Start, node.Arguments.Count))
                            : 0;
                    }

                    if (methodArguments.IsEmpty)
                        resolved.Add((frame.Signature, owner), value);
                    else
                        methodResults![frame.Signature] = new(methodGeneration, value);

                    active[frame.Signature] = false;
                    start = frame.Start;
                    --depth;
                }

                if (depth == 0)
                    return value;
            }
        } finally {
            // Pending frames retire after a failure. Completed immutable answers
            // remain reusable in their original owner or query generation.
            while (depth != 0) {
                int unfinished = frames[--depth].Signature;
                active[unfinished] = false;
            }
        }
    }
}
