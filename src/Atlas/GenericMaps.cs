using System.Runtime.InteropServices;

namespace Atlas;

public readonly struct GenericTypeEntry(int vertex, ulong methodTable) {
    public readonly int Vertex = vertex;
    public readonly ulong MethodTable = methodTable;
}

public struct GenericMethodEntry {
    public int Section;
    public int Vertex;
    internal int Signature;

    public ulong DeclaringType;
    public ulong Dictionary;
    public ulong Entrypoint;

    public uint Token;
    public uint MetadataOffset;
    public uint NativeOffset;

    public string Name;
    public bool AsyncVariant;
    public IndexRange Arguments;
}

public sealed class GenericMaps {
    internal readonly List<GenericTypeEntry> Types = new();
    internal readonly List<GenericMethodEntry> Methods = new();
    internal readonly List<ulong> Arguments = new();

    public ReadOnlySpan<GenericTypeEntry> TypeEntries => CollectionsMarshal.AsSpan(Types);
    public ReadOnlySpan<GenericMethodEntry> MethodEntries => CollectionsMarshal.AsSpan(Methods);
    public ReadOnlySpan<ulong> ArgumentAddresses => CollectionsMarshal.AsSpan(Arguments);

    internal void Read(
        PeImage image,
        ReadyToRun rtr,
        Metadata metadata,
        NativeLayout layout,
        ReadOnlySpan<ulong> references,
        MapFormat format,
        CancellationToken cancellationToken = default) {
        cancellationToken.ThrowIfCancellationRequested();

        var section = rtr.Find(RtrSectionId.GenericsHashtable);
        var data = section.Length == 0
            ? default
            : image.FileSpan(section.Start, checked((int)section.Length));
        var table = new NativeTable(data);

        if (table.MoveNext()) {
            Types.EnsureCapacity(65536);

            do {
                cancellationToken.ThrowIfCancellationRequested();

                var reader = new NativeReader(data, table.Vertex);
                Types.Add(new GenericTypeEntry(table.Vertex, Reference(ref reader, references)));
            } while (table.MoveNext());
        }

        bool maskedToken = rtr.Format.MaskedGenericMethodTokens;

        ReadOnlySpan<RtrSectionId> methodMaps = [
            RtrSectionId.GenericMethodsHashtable,
            RtrSectionId.ExactMethodInstantiationsHashtable
        ];

        foreach (var id in methodMaps) {
            section = rtr.Find(id);
            data = section.Length == 0
                ? default
                : image.FileSpan(section.Start, checked((int)section.Length));
            table = new NativeTable(data);

            if (!table.MoveNext())
                continue;

            Methods.EnsureCapacity(32768);

            do {
                cancellationToken.ThrowIfCancellationRequested();

                var reader = new NativeReader(data, table.Vertex);
                GenericMethodEntry entry = new() {
                    Section = (int)id,
                    Vertex = table.Vertex
                };

                if (id == RtrSectionId.GenericMethodsHashtable)
                    entry.Dictionary = Reference(ref reader, references);

                entry.DeclaringType = Reference(ref reader, references);
                entry.Token = reader.Unsigned();

                int count = checked((int)reader.Unsigned());
                if (count > reader.Remaining)
                    throw new InvalidDataException("Generic method arguments exceed storage.");

                entry.Arguments = new IndexRange(Arguments.Count, count);
                if (count != 0)
                    Arguments.EnsureCapacity(Math.Max(65536, checked(Arguments.Count + count)));

                for (int i = 0; i < count; ++i)
                    Arguments.Add(Reference(ref reader, references));

                if (id == RtrSectionId.ExactMethodInstantiationsHashtable) {
                    entry.Entrypoint = Reference(ref reader, references);
                    if (!image.IsExecutable(entry.Entrypoint))
                        throw new InvalidDataException(
                            "Exact method instantiation entrypoint is outside executable storage.");
                }

                var identity = MethodIdentity.Read(entry.Token, metadata, layout, format, maskedToken);
                entry.MetadataOffset = identity.MetadataOffset;
                entry.NativeOffset = identity.NativeOffset;
                entry.Name = identity.Name;
                entry.Signature = identity.Signature;
                entry.AsyncVariant = identity.AsyncVariant;

                if (metadata.SignatureBuilder.Methods[entry.Signature].GenericParameterCount != count)
                    throw new InvalidDataException($"Generic method '{entry.Name}' has a mismatched instantiation arity.");

                Methods.Add(entry);
            } while (table.MoveNext());
        }
    }

    private static ulong Reference(ref NativeReader reader, ReadOnlySpan<ulong> references) {
        uint index = reader.Unsigned();
        if (index >= references.Length || references[(int)index] == 0)
            throw new InvalidDataException("Generic map refers outside NativeReferences or to null.");

        return references[(int)index];
    }
}
