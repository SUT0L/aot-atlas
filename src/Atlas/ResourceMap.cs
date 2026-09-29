using System.Buffers;
using System.Numerics;
using System.Text;

namespace Atlas;

public readonly struct ResourceEntry(int indexOffset, IndexRange assembly, IndexRange name, IndexRange data) {
    public readonly int IndexOffset = indexOffset;
    public readonly IndexRange Assembly = assembly;
    public readonly IndexRange Name = name;
    public readonly IndexRange Data = data;
}

public sealed class ResourceMap {
    public readonly ulong IndexStart, DataStart;
    public readonly ReadOnlyMemory<byte> IndexData, Data;
    public readonly List<ResourceEntry> Entries = new(64);

    public ResourceMap(PeImage image, ReadyToRun rtr) {
        var indexSection = rtr.Find(324);
        var dataSection = rtr.Find(325);
        IndexStart = indexSection.Start;
        DataStart = dataSection.Start;
        IndexData = indexSection.Length == 0 ? default : image.FileMemory(IndexStart, checked((int)indexSection.Length));
        Data = dataSection.Length == 0 ? default : image.FileMemory(DataStart, checked((int)dataSection.Length));

        if (IndexData.IsEmpty && !Data.IsEmpty)
            throw new InvalidDataException("Resource data has no resource index.");

        var bytes = IndexData.Span;
        var table = new NativeTable(bytes);
        var utf8 = new UTF8Encoding(false, true);
        Span<uint> hashes = stackalloc uint[2];
        while (table.MoveNext()) {
            var reader = new NativeReader(bytes, table.Vertex);
            int length = checked((int)reader.Unsigned());
            var assembly = new IndexRange(reader.Position, length);
            var assemblyName = reader.Take(length);

            // Runtime lookup hashes UTF-16 code units, including both halves of a supplementary character
            // Keep names in their source bytes
            hashes[0] = 0x6DA3B944;
            hashes[1] = 0;
            int codeUnit = 0;
            while (!assemblyName.IsEmpty) {
                if (Rune.DecodeFromUtf8(assemblyName, out var rune, out int consumed) != OperationStatus.Done)
                    throw new InvalidDataException("Invalid UTF-8 resource assembly name.");

                uint scalar = (uint)rune.Value;
                int units = scalar > 0xFFFF ? 2 : 1;
                for (int i = 0; i < units; ++i) {
                    uint value = units == 1 ? scalar : i == 0 ? ((scalar - 0x10000) >> 10) + 0xD800 : ((scalar - 0x10000) & 0x3FF) + 0xDC00;
                    ref uint hash = ref hashes[codeUnit++ & 1];
                    hash = (hash + BitOperations.RotateLeft(hash, 5)) ^ value;
                }
                assemblyName = assemblyName[consumed..];
            }

            uint nameHash = (hashes[0] + BitOperations.RotateLeft(hashes[0], 8)) ^ (hashes[1] + BitOperations.RotateLeft(hashes[1], 8));
            if (table.LowHash != (byte)nameHash || table.Bucket != ((nameHash >> 8) & (uint)table.BucketMask))
                throw new InvalidDataException("Resource assembly hash does not match its runtime lookup bucket.");

            length = checked((int)reader.Unsigned());
            var name = new IndexRange(reader.Position, length);
            utf8.GetCharCount(reader.Take(length));

            int offset = checked((int)reader.Unsigned());
            length = checked((int)reader.Unsigned());
            if (offset > Data.Length || length > Data.Length - offset)
                throw new InvalidDataException("Resource payload exceeds the resource data blob.");

            Entries.Add(new ResourceEntry(table.Vertex, assembly, name, new IndexRange(offset, length)));
        }

        if (Entries.Count != 0 && dataSection.Start == 0)
            throw new InvalidDataException("Resource index has no resource data blob.");
    }
}
