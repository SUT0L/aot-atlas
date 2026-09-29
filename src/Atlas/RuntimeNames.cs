using System.Runtime.InteropServices;
using System.Text;

namespace Atlas;

public sealed class RuntimeNames {
    public readonly string[] Values;
    public readonly bool[] Complete;

    public RuntimeNames(MethodTables tables, ReflectionMaps maps) {
        int count = tables.Types.Count;
        Values = new string[count];
        Complete = new bool[count];
        var state = new byte[count];

        foreach (ref readonly var entry in CollectionsMarshal.AsSpan(maps.Types)) {
            int index = tables.Index[entry.MethodTable];
            if (state[index] != 0 && Values[index] != entry.Name)
                throw new InvalidDataException($"Conflicting TypeMap names at 0x{entry.MethodTable:X}.");

            Values[index] = entry.Name;
            Complete[index] = true;
            state[index] = 2;
        }

        // Follow identity dependencies, never base classes or interfaces
        // Each type finishes once, even when many parents share its name
        var stack = new (int Type, int Next)[count];
        var builder = new StringBuilder(256);
        var types = CollectionsMarshal.AsSpan(tables.Types);
        var pointers = CollectionsMarshal.AsSpan(tables.Pointers);

        for (int root = 0; root < count; ++root) {
            if (state[root] == 2)
                continue;

            stack[0] = (root, 0);
            state[root] = 1;
            int depth = 0;

            while (depth >= 0) {
                ref var frame = ref stack[depth];
                int index = frame.Type;
                ref readonly var type = ref types[index];
                int dependencies = type.IsGeneric || type.Kind == 1 ? 1 + type.Arguments.Count : type.Kind == 2 ? 1 : 0;
                ulong primary = type.IsGeneric ? type.GenericDefinition : type.RelatedType;

                if (frame.Next < dependencies) {
                    int edge = frame.Next++;
                    ulong address = edge == 0 ? primary : pointers[type.Arguments.Start + edge - 1];
                    int child = tables.Index[address];

                    if (state[child] == 1)
                        throw new InvalidDataException($"Cyclic runtime type identity at 0x{address:X}.");

                    if (state[child] == 0) {
                        state[child] = 1;
                        stack[++depth] = (child, 0);
                    }

                    continue;
                }

                builder.Clear();
                if (dependencies == 0) {
                    builder.Append("mt_ref_").Append(type.Address.ToString("X"));
                } else {
                    int first = tables.Index[primary];
                    bool complete = Complete[first];

                    if (type.Kind == 1) {
                        builder.Append("delegate*");
                        if ((type.BaseSize & 0x80000000) != 0)
                            builder.Append(" unmanaged");

                        builder.Append('<');
                    } else {
                        builder.Append(Values[first]);
                        if (type.IsGeneric)
                            builder.Append('<');
                    }

                    for (int i = type.Arguments.Start; i < type.Arguments.End; ++i) {
                        int argument = tables.Index[pointers[i]];
                        if (i != type.Arguments.Start)
                            builder.Append(',');

                        builder.Append(Values[argument]);
                        complete &= Complete[argument];
                    }

                    if (type.IsGeneric) {
                        builder.Append('>');
                    } else if (type.Kind == 1) {
                        if (type.Arguments.Count != 0)
                            builder.Append(',');

                        builder.Append(Values[first]).Append('>');
                    } else if (type.ElementType is 0x17 or 0x18) {
                        builder.Append('[');
                        if (type.ElementType == 0x17) {
                            int rank = checked((int)(type.BaseSize - 24) / 8);
                            if (rank == 1)
                                builder.Append('*');
                            else
                                builder.Append(',', rank - 1);
                        }

                        builder.Append(']');
                    } else {
                        builder.Append(type.ElementType == 0x19 ? '&' : '*');
                    }

                    Complete[index] = complete;
                }

                Values[index] = builder.ToString();
                state[index] = 2;
                --depth;
            }
        }
    }
}
