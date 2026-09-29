namespace Atlas;

public readonly struct TypeTemplate(int vertex, ulong methodTable, uint layoutOffset) {
    public readonly int Vertex = vertex;
    public readonly ulong MethodTable = methodTable;
    public readonly uint LayoutOffset = layoutOffset;
}

public struct MethodTemplate {
    public int Vertex;
    public uint LayoutOffset;
    public NativeMethodEntry Method;
    public bool UniversalCanonical, AsyncVariant;
}

public sealed class TemplateMaps {
    public readonly List<TypeTemplate> Types = new(8192);
    public readonly List<MethodTemplate> Methods = new(8192);

    public void Read(PeImage image, ReadyToRun rtr, Metadata metadata, NativeLayout layout, ReadOnlySpan<ulong> fixups, MapFormat format) {
        ulong layoutLength = rtr.Find(330).Length;
        for (int id = 321; id <= 322; ++id) {
            var section = rtr.Find(id);
            var data = section.Length == 0 ? default : image.FileSpan(section.Start, checked((int)section.Length));
            var table = new NativeTable(data);

            while (table.MoveNext()) {
                var reader = new NativeReader(data, table.Vertex);
                uint reference = reader.Unsigned();
                uint offset = reader.Unsigned();
                if (offset == uint.MaxValue)
                    throw new InvalidDataException("Template map contains an unresolved layout fixup.");
                if (offset >= layoutLength)
                    throw new InvalidDataException("Template layout offset exceeds NativeLayout storage.");

                if (id == 321) {
                    if (reference >= fixups.Length || fixups[(int)reference] == 0)
                        throw new InvalidDataException("Type template refers outside CommonFixups or to null.");

                    Types.Add(new TypeTemplate(table.Vertex, fixups[(int)reference], offset));
                } else {
                    var entry = layout.MethodEntry(reference, metadata, format);
                    if (entry.Arguments.Count == 0)
                        throw new InvalidDataException("Generic method template has no instantiation.");
                    if (entry.Entrypoint != 0 && !image.IsExecutable(entry.Entrypoint))
                        throw new InvalidDataException("Method template entrypoint is outside executable storage.");

                    bool variant = (entry.Flags & 8) != 0;
                    if (variant && rtr.Major is > 12 and < 18)
                        throw new InvalidDataException("Method template has a reserved variant flag.");
                    if (variant && rtr.Major <= 12 && entry.Entrypoint == 0)
                        throw new InvalidDataException("Universal canonical method template has no entrypoint.");

                    Methods.Add(new MethodTemplate {
                        Vertex = table.Vertex,
                        LayoutOffset = offset,
                        Method = entry,
                        UniversalCanonical = variant && rtr.Major <= 12,
                        AsyncVariant = variant && rtr.Major >= 18
                    });
                }
            }
        }
    }
}
