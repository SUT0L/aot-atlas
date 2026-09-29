using System.Runtime.InteropServices;

namespace Atlas;

public sealed class CanonicalTypes {
    public readonly int[] Groups;

    public CanonicalTypes(MethodTables tables) {
        int count = tables.Types.Count;
        Groups = new int[count];
        var next = new int[count];
        var state = new byte[count];
        var stack = new (int Type, int Next)[count];
        var heads = new Dictionary<(ulong Definition, ulong Hash, int Count), int>(count);
        var types = CollectionsMarshal.AsSpan(tables.Types);

        for (int i = 0; i < count; ++i) {
            if (!types[i].IsGeneric) {
                Groups[i] = i + 1;
                state[i] = 2;
            }
        }

        for (int root = 0; root < count; ++root) {
            if (state[root] == 2)
                continue;

            int depth = 0;
            stack[0] = (root, 0);
            state[root] = 1;
            while (depth >= 0) {
                ref var frame = ref stack[depth];
                ref readonly var type = ref types[frame.Type];
                if (frame.Next < type.Arguments.Count) {
                    int child = tables.Index[tables.Pointers[type.Arguments.Start + frame.Next++]];
                    if (!types[child].IsValueType)
                        continue;
                    if (state[child] == 1)
                        throw new InvalidDataException("Cyclic value-type generic composition.");

                    if (state[child] == 0) {
                        state[child] = 1;
                        stack[++depth] = (child, 0);
                    }
                    continue;
                }

                ulong hash = 14695981039346656037UL;
                for (int i = type.Arguments.Start; i < type.Arguments.End; ++i)
                    hash = unchecked((hash ^ (uint)Argument(tables, tables.Index[tables.Pointers[i]])) * 1099511628211UL);

                var key = (type.GenericDefinition, hash, type.Arguments.Count);
                ref int head = ref CollectionsMarshal.GetValueRefOrAddDefault(heads, key, out _);
                int group = 0;
                for (int candidate = head; candidate != 0; candidate = next[candidate - 1]) {
                    ref readonly var other = ref types[candidate - 1];
                    bool match = true;
                    for (int i = 0; i < type.Arguments.Count; ++i) {
                        int left = tables.Index[tables.Pointers[type.Arguments.Start + i]];
                        int right = tables.Index[tables.Pointers[other.Arguments.Start + i]];
                        match &= Argument(tables, left) == Argument(tables, right);
                    }

                    if (match) {
                        group = candidate;
                        break;
                    }
                }

                if (group == 0) {
                    group = frame.Type + 1;
                    next[frame.Type] = head;
                    head = group;
                }

                Groups[frame.Type] = group;
                state[frame.Type] = 2;
                --depth;
            }
        }
    }

    public int Argument(MethodTables tables, int index) {
        ref readonly var type = ref CollectionsMarshal.AsSpan(tables.Types)[index];
        // Specific canonicalization collapses reference arguments, including arrays, but preserves value identity and nested value composition
        if ((type.Kind == 0 && type.ElementType is >= 0x14 and <= 0x16)
            || (type.Kind == 2 && type.ElementType is 0x17 or 0x18))
            return 0;

        return Groups[index];
    }
}
