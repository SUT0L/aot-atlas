using System.Runtime.InteropServices;

namespace Atlas;

// Runtime identities belong to one completed binding input. Retain only the
// addresses and generic arguments used by resolution, never the mutable tables.
internal sealed class RuntimeTypeIndex {
    private readonly record struct Target(ulong Address, IndexRange Arguments);
    private readonly record struct GenericCandidate(int Binding, int Next);

    private readonly Target[] targets;
    private readonly ulong[] arguments;
    private readonly GenericCandidate[] candidates;

    private readonly Dictionary<ulong, int> addresses;
    private readonly Dictionary<(ulong Definition, ulong Hash, int Count), int> instantiations;
    private readonly Dictionary<(int Kind, int Rank, ulong Element), int> parameterized;

    internal RuntimeTypeIndex(MethodTables tables)
        : this(CollectionsMarshal.AsSpan(tables.Types), CollectionsMarshal.AsSpan(tables.Pointers)) {
    }

    internal RuntimeTypeIndex(RuntimeTypePublication tables)
        : this(tables.TypeEntries, tables.PointerValues) {
    }

    private RuntimeTypeIndex(ReadOnlySpan<MethodTable> types, ReadOnlySpan<ulong> pointers) {

        int genericCount = 0;
        int parameterizedCount = 0;
        int argumentCount = 0;

        foreach (ref readonly var type in types) {
            if (type.IsGeneric) {
                ++genericCount;
                argumentCount = checked(argumentCount + type.Arguments.Count);
            } else if (type.Kind == 2) {
                ++parameterizedCount;
            }
        }

        targets = new Target[types.Length];
        arguments = new ulong[argumentCount];
        candidates = new GenericCandidate[genericCount];

        addresses = new(types.Length);
        instantiations = new(genericCount);
        parameterized = new(parameterizedCount);

        int cursor = 0;
        int generic = 0;

        for (int i = 0; i < types.Length; ++i) {
            ref readonly var type = ref types[i];
            addresses.Add(type.Address, i + 1);
            var range = default(IndexRange);

            if (type.IsGeneric) {
                range = new(cursor, type.Arguments.Count);
                pointers.Slice(type.Arguments.Start, type.Arguments.Count)
                    .CopyTo(arguments.AsSpan(cursor));
                cursor += range.Count;

                var key = (type.GenericDefinition, Hash(arguments.AsSpan(range.Start, range.Count)), range.Count);
                ref int head = ref CollectionsMarshal.GetValueRefOrAddDefault(instantiations, key, out _);
                candidates[generic] = new(i + 1, head);
                head = ++generic;
            } else if (type.Kind == 2) {
                int rank = type.ElementType == 0x17 ? checked((int)(type.BaseSize - 24) / 8) : 0;
                var key = (type.ElementType, rank, type.RelatedType);
                ref int slot = ref CollectionsMarshal.GetValueRefOrAddDefault(parameterized, key, out _);
                slot = slot == 0 || slot == i + 1 ? i + 1 : -1;
            }

            targets[i] = new(type.Address, range);
        }
    }

    internal int Binding(ulong address) => addresses[address];
    internal ulong Address(int binding) => targets[binding - 1].Address;

    internal int Argument(int owner, int parameter) {
        var range = targets[owner - 1].Arguments;

        return (uint)parameter < (uint)range.Count
            ? Binding(arguments[range.Start + parameter])
            : 0;
    }

    internal int Instantiation(ulong definition, ReadOnlySpan<ulong> values) {
        if (!instantiations.TryGetValue((definition, Hash(values), values.Length), out int candidate))
            return 0;

        int result = 0;

        for (; candidate != 0; candidate = candidates[candidate - 1].Next) {
            int binding = candidates[candidate - 1].Binding;
            var range = targets[binding - 1].Arguments;

            if (!values.SequenceEqual(arguments.AsSpan(range.Start, range.Count)))
                continue;

            if (result != 0)
                return 0;

            result = binding;
        }

        return result;
    }

    internal int Parameterized(int kind, int rank, ulong element) =>
        parameterized.TryGetValue((kind, rank, element), out int binding) ? Math.Max(0, binding) : 0;

    private static ulong Hash(ReadOnlySpan<ulong> values) {
        ulong hash = 14695981039346656037UL;

        foreach (ulong value in values)
            hash = unchecked((hash ^ value) * 1099511628211UL);

        return hash;
    }
}
