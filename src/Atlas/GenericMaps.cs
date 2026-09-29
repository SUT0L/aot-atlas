namespace Atlas;

public readonly struct GenericTypeEntry(int vertex, ulong methodTable) {
    public readonly int Vertex = vertex;
    public readonly ulong MethodTable = methodTable;
}

public struct GenericMethodEntry {
    public int Section, Vertex, Signature;
    public ulong DeclaringType, Dictionary, Entrypoint;
    public uint Token, MetadataOffset, NativeOffset;
    public string Name;
    public bool AsyncVariant;
    public IndexRange Arguments;
}

public sealed class GenericMaps {
    public readonly List<GenericTypeEntry> Types = new(65536);
    public readonly List<GenericMethodEntry> Methods = new(32768);
    public readonly List<ulong> Arguments = new(65536);

    public void Read(PeImage image, ReadyToRun rtr, Metadata metadata, NativeLayout layout, ReadOnlySpan<ulong> references, MapFormat format) {
        var section = rtr.Find(332);
        var data = section.Length == 0 ? default : image.FileSpan(section.Start, checked((int)section.Length));
        var table = new NativeTable(data);

        while (table.MoveNext()) {
            var reader = new NativeReader(data, table.Vertex);
            Types.Add(new GenericTypeEntry(table.Vertex, Reference(ref reader, references)));
        }

        bool maskedToken = rtr.Major > 18 || (rtr.Major == 18 && rtr.Minor >= 4);

        for (int id = 335; id <= 336; ++id) {
            section = rtr.Find(id);
            data = section.Length == 0 ? default : image.FileSpan(section.Start, checked((int)section.Length));
            table = new NativeTable(data);

            while (table.MoveNext()) {
                var reader = new NativeReader(data, table.Vertex);
                GenericMethodEntry entry = new() { Section = id, Vertex = table.Vertex };
                if (id == 335)
                    entry.Dictionary = Reference(ref reader, references);

                entry.DeclaringType = Reference(ref reader, references);
                entry.Token = reader.Unsigned();
                int count = checked((int)reader.Unsigned());
                if (count > reader.Remaining)
                    throw new InvalidDataException("Generic method arguments exceed storage.");

                entry.Arguments = new IndexRange(Arguments.Count, count);
                Arguments.EnsureCapacity(checked(Arguments.Count + count));
                for (int i = 0; i < count; ++i)
                    Arguments.Add(Reference(ref reader, references));

                if (id == 336) {
                    entry.Entrypoint = Reference(ref reader, references);
                    if (!image.IsExecutable(entry.Entrypoint))
                        throw new InvalidDataException("Exact method instantiation entrypoint is outside executable storage.");
                }

                var identity = MethodIdentity.Read(entry.Token, metadata, layout, format, maskedToken);
                entry.MetadataOffset = identity.MetadataOffset;
                entry.NativeOffset = identity.NativeOffset;
                entry.Name = identity.Name;
                entry.Signature = identity.Signature;
                entry.AsyncVariant = identity.AsyncVariant;

                if (metadata.Signatures.Methods[entry.Signature].GenericParameterCount != count)
                    throw new InvalidDataException($"Generic method '{entry.Name}' has a mismatched instantiation arity.");

                Methods.Add(entry);
            }
        }
    }

    private static ulong Reference(ref NativeReader reader, ReadOnlySpan<ulong> references) {
        uint index = reader.Unsigned();
        if (index >= references.Length || references[(int)index] == 0)
            throw new InvalidDataException("Generic map refers outside NativeReferences or to null.");

        return references[(int)index];
    }
}
