using System.Runtime.InteropServices;

namespace Atlas;

public sealed class TypeBindings {
    private readonly MethodTables tables;
    private readonly Signatures signatures;
    private readonly int[] named, next;
    private readonly ulong[] arguments;
    private readonly Dictionary<(ulong Definition, ulong Hash, int Count), int> instantiations = new(32768);
    private readonly Dictionary<(int Kind, int Rank, ulong Element), int> parameterized = new(4096);
    private readonly Dictionary<(int Signature, int Owner), int> resolved = new(4096);

    public TypeBindings(MethodTables tables, ReflectionMaps maps, Signatures signatures) {
        this.tables = tables;
        this.signatures = signatures;
        named = new int[signatures.Nodes.Count];
        next = new int[tables.Types.Count];
        arguments = new ulong[signatures.Edges.Count];

        foreach (ref readonly var entry in CollectionsMarshal.AsSpan(maps.Types)) {
            int binding = tables.Index[entry.MethodTable] + 1;
            ref int slot = ref named[entry.Signature];
            slot = slot == 0 || slot == binding ? binding : -1;
        }

        for (int i = 0; i < tables.Types.Count; ++i) {
            ref readonly var type = ref CollectionsMarshal.AsSpan(tables.Types)[i];
            if (type.IsGeneric) {
                ulong hash = 14695981039346656037UL;
                for (int j = type.Arguments.Start; j < type.Arguments.End; ++j)
                    hash = unchecked((hash ^ tables.Pointers[j]) * 1099511628211UL);

                var key = (type.GenericDefinition, hash, type.Arguments.Count);
                ref int head = ref CollectionsMarshal.GetValueRefOrAddDefault(instantiations, key, out _);
                next[i] = head;
                head = i + 1;
            } else if (type.Kind == 2) {
                int rank = type.ElementType == 0x17 ? checked((int)(type.BaseSize - 24) / 8) : 0;
                var key = (type.ElementType, rank, type.RelatedType);
                ref int slot = ref CollectionsMarshal.GetValueRefOrAddDefault(parameterized, key, out _);
                slot = slot == 0 || slot == i + 1 ? i + 1 : -1;
            }
        }
    }

    // A binding is an index plus one
    // Zero means no unique runtime identity; names and coincidentally equal sizes cant resolve that uncertainty
    public int Resolve(int signature, int owner = 0, ReadOnlySpan<ulong> methodArguments = default) => Resolve(signature, owner, methodArguments, 0);

    private int Resolve(int signature, int owner, ReadOnlySpan<ulong> methodArguments, int scratch) {
        ref readonly var node = ref CollectionsMarshal.AsSpan(signatures.Nodes)[signature];
        if (node.TypeAddress != 0)
            return tables.Index[node.TypeAddress] + 1;
        if (node.Kind == SignatureKind.Named)
            return Math.Max(0, named[signature]);
        if (node.Kind == SignatureKind.Modified)
            return Resolve(node.Element, owner, methodArguments, scratch);
        if (node.Kind == SignatureKind.MethodVariable)
            return node.Value < methodArguments.Length ? tables.Index[methodArguments[node.Value]] + 1 : 0;
        if (node.Kind == SignatureKind.TypeVariable) {
            if (owner == 0)
                return 0;

            var args = tables.Types[owner - 1].Arguments;
            return node.Value < args.Count ? tables.Index[tables.Pointers[args.Start + node.Value]] + 1 : 0;
        }

        if (node.Kind is not (SignatureKind.Instantiation or SignatureKind.Array or SignatureKind.SzArray or SignatureKind.Pointer or SignatureKind.ByReference))
            return 0;
        // The persistent cache belongs to type instantiations
        // Method arguments are borrowed from the current record and must never reuse another methods result
        if (methodArguments.IsEmpty && resolved.TryGetValue((signature, owner), out int cached))
            return cached;

        int element = Resolve(node.Element, owner, methodArguments, scratch);
        int result = 0;
        if (element != 0) {
            ulong address = tables.Types[element - 1].Address;
            if (node.Kind == SignatureKind.Instantiation) {
                ulong hash = 14695981039346656037UL;
                bool complete = true;
                for (int i = 0; i < node.Arguments.Count; ++i) {
                    int binding = Resolve(signatures.Edges[node.Arguments.Start + i], owner, methodArguments, scratch + node.Arguments.Count);
                    ulong argument = binding == 0 ? 0 : tables.Types[binding - 1].Address;
                    arguments[scratch + i] = argument;
                    hash = unchecked((hash ^ argument) * 1099511628211UL);
                    complete &= binding != 0;
                }

                if (complete && instantiations.TryGetValue((address, hash, node.Arguments.Count), out int candidate)) {
                    for (; candidate != 0; candidate = next[candidate - 1]) {
                        var args = tables.Types[candidate - 1].Arguments;
                        bool match = true;
                        for (int i = 0; i < args.Count; ++i)
                            match &= tables.Pointers[args.Start + i] == arguments[scratch + i];

                        if (match) {
                            if (result != 0) {
                                result = 0;
                                break;
                            }
                            result = candidate;
                        }
                    }
                }
            } else {
                int kind = node.Kind switch {
                    SignatureKind.Array => 0x17,
                    SignatureKind.SzArray => 0x18,
                    SignatureKind.ByReference => 0x19,
                    _ => 0x1A
                };
                if (parameterized.TryGetValue((kind, kind == 0x17 ? node.Value : 0, address), out int binding))
                    result = Math.Max(0, binding);
            }
        }

        if (methodArguments.IsEmpty)
            resolved.Add((signature, owner), result);
        return result;
    }
}
