using System.Runtime.InteropServices;
using System.Text;

namespace Atlas;

public sealed class RuntimeNames {
    private const int MaximumDerivedNameLength = 4096;

    internal readonly string[] Values;
    internal readonly bool[] Complete;
    public ReadOnlySpan<string> Names => Values;
    public ReadOnlySpan<bool> Completeness => Complete;

    public RuntimeNames(MethodTables tables, ReflectionMaps maps) {
        int count = tables.Types.Count;
        Values = new string[count];
        Complete = new bool[count];

        var order = new int[count];
        tables.ValidateIdentityTypes(order);

        foreach (ref readonly var entry in CollectionsMarshal.AsSpan(maps.Types)) {
            int index = tables.Index[entry.MethodTable];
            if (Values[index] is not null && Values[index] != entry.Name)
                throw new InvalidDataException($"Conflicting TypeMap names at 0x{entry.MethodTable:X}.");

            Values[index] = entry.Name;
            Complete[index] = true;
        }

        var builder = new NameBuilder();
        var types = CollectionsMarshal.AsSpan(tables.Types);

        foreach (int index in order) {
            if (Values[index] is not null)
                continue;

            ref readonly var type = ref types[index];
            builder.Clear();
            if (!Render(builder, type, tables, Values, false, out bool complete)) {
                builder.Clear();
                if (!Render(builder, type, tables, Values, true, out _)) {
                    builder.Clear();
                    builder.Append("mt_ref_").Append(type.Address.ToString("X"));
                }

                complete = false;
            }

            Complete[index] = complete;
            Values[index] = builder.ToString();
        }
    }

    private bool Render(
        NameBuilder builder,
        in MethodTable type,
        MethodTables tables,
        string[] names,
        bool references,
        out bool complete) {
        complete = false;
        int dependencies = MethodTables.IdentityDependencyCount(type);
        ulong primary = type.IsGeneric ? type.GenericDefinition : type.RelatedType;
        var pointers = CollectionsMarshal.AsSpan(tables.Pointers);

        if (dependencies == 0) {
            builder.Append("mt_ref_").Append(type.Address.ToString("X"));
        } else {
            int first = tables.Index[primary];
            complete = Complete[first];

            if (type.Kind == 1) {
                builder.Append("delegate*");
                if ((type.BaseSize & 0x80000000) != 0)
                    builder.Append(" unmanaged");

                builder.Append('<');
            } else {
                AppendDependency(builder, tables, names, first, references);
                if (type.IsGeneric)
                    builder.Append('<');
            }

            for (int i = type.Arguments.Start; i < type.Arguments.End; ++i) {
                int argument = tables.Index[pointers[i]];
                if (i != type.Arguments.Start)
                    builder.Append(',');

                AppendDependency(builder, tables, names, argument, references);
                if (!builder.Fits)
                    return false;

                complete &= Complete[argument];
            }

            if (type.IsGeneric) {
                builder.Append('>');
            } else if (type.Kind == 1) {
                if (type.Arguments.Count != 0)
                    builder.Append(',');

                AppendDependency(builder, tables, names, first, references);
                builder.Append('>');
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

            complete = complete && !references;
        }

        return builder.Fits;
    }

    private static void AppendDependency(
        NameBuilder builder,
        MethodTables tables,
        string[] names,
        int index,
        bool reference) {
        if (reference)
            builder.Append("mt_ref_").Append(tables.Types[index].Address.ToString("X"));
        else
            builder.Append(names[index]);
    }

    // Every append establishes the output bound. Rendering rules do not need a
    // separate length grammar, and an incomplete attempt is never published.
    private sealed class NameBuilder {
        private readonly StringBuilder builder = new(256);

        internal bool Fits { get; private set; } = true;

        internal void Clear() {
            builder.Clear();
            Fits = true;
        }

        internal NameBuilder Append(string value) {
            if (Fits && value.Length <= MaximumDerivedNameLength - builder.Length)
                builder.Append(value);
            else
                Fits = false;

            return this;
        }

        internal NameBuilder Append(char value) {
            if (Fits && builder.Length < MaximumDerivedNameLength)
                builder.Append(value);
            else
                Fits = false;

            return this;
        }

        internal NameBuilder Append(char value, int count) {
            if (Fits && count <= MaximumDerivedNameLength - builder.Length)
                builder.Append(value, count);
            else
                Fits = false;

            return this;
        }

        public override string ToString() => builder.ToString();
    }
}
