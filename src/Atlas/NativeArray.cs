using System.Buffers.Binary;
using System.Runtime.CompilerServices;

namespace Atlas;

// NativeFormat VertexArray: a block index followed by sparse, four-level trees.
public ref struct NativeArray {
    private readonly ReadOnlySpan<byte> data;
    private readonly int table;
    private readonly int tableEnd;
    private readonly int indexSize;
    private int nextBlock;
    private int blockBase;
    private Frames pending;
    private int pendingCount;

    private readonly record struct Frame(int Offset, int Prefix, int Bit);

    [InlineArray(4)]
    private struct Frames {
        private Frame first;
    }

    public int Count { get; }
    public int Index { get; private set; }
    public int Vertex { get; private set; }

    public NativeArray(ReadOnlySpan<byte> bytes) {
        data = bytes;
        var reader = new NativeReader(bytes);
        uint header = reader.Unsigned();
        int sizeCode = (int)(header & 3);
        if (sizeCode == 3)
            throw new InvalidDataException("Invalid NativeArray index size.");

        Count = (int)(header >> 2);
        indexSize = 1 << sizeCode;
        table = reader.Position;
        long end = table + ((long)Count + 15) / 16 * indexSize;
        if (end > bytes.Length)
            throw new InvalidDataException("Truncated NativeArray index.");

        tableEnd = (int)end;
    }

    public bool MoveNext() {
        while (true) {
            Frame frame;
            if (pendingCount != 0) {
                frame = pending[--pendingCount];
            } else {
                if (nextBlock >= (Count + 15) / 16)
                    return false;

                blockBase = nextBlock * 16;
                var entry = data[(table + nextBlock * indexSize)..];
                ++nextBlock;
                uint relative = indexSize switch {
                    1 => entry[0],
                    2 => BinaryPrimitives.ReadUInt16LittleEndian(entry),
                    _ => BinaryPrimitives.ReadUInt32LittleEndian(entry)
                };
                frame = new Frame(Target(table, relative), 0, 8);
            }

            while (true) {
                // At the fourth level, children are payloads without another node header.
                if (frame.Bit == 0) {
                    SetEntry(frame.Prefix, frame.Offset);
                    return true;
                }

                var reader = new NativeReader(data, frame.Offset);
                uint node = reader.Unsigned();
                uint flags = node & 3;
                if (flags == 0) {
                    int leaf = (int)(node >> 2);
                    if (leaf == 16 && frame.Bit == 8 && frame.Prefix == 0)
                        break;

                    if (leaf < frame.Prefix || leaf >= frame.Prefix + 2 * frame.Bit)
                        throw new InvalidDataException("NativeArray leaf is outside its subtree.");

                    SetEntry(leaf, reader.Position);
                    return true;
                }

                if ((flags & 2) != 0) {
                    uint delta = node >> 2;
                    int right = Target(frame.Offset, delta);
                    if (delta == 0 || right < reader.Position)
                        throw new InvalidDataException("NativeArray branch overlaps its header.");

                    var next = new Frame(right, frame.Prefix + frame.Bit, frame.Bit >> 1);
                    if ((flags & 1) == 0) {
                        frame = next;
                        continue;
                    }

                    pending[pendingCount++] = next;
                }

                frame = new Frame(reader.Position, frame.Prefix, frame.Bit >> 1);
            }
        }
    }

    private void SetEntry(int localIndex, int vertex) {
        int index = blockBase + localIndex;
        if (index >= Count || vertex < tableEnd || vertex >= data.Length)
            throw new InvalidDataException("NativeArray entry is outside storage or its logical count.");

        Index = index;
        Vertex = vertex;
    }

    private readonly int Target(int origin, uint relative) {
        long target = (long)origin + relative;
        if (target < tableEnd || target >= data.Length)
            throw new InvalidDataException("NativeArray target is outside storage or overlaps its index.");

        return (int)target;
    }
}
