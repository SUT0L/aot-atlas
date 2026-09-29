using System.Buffers.Binary;
using System.Text;

namespace Atlas;

public ref struct NativeReader(ReadOnlySpan<byte> bytes, int position = 0) {
    private readonly ReadOnlySpan<byte> data = bytes;
    public int Position = position;
    public int Remaining => data.Length - Position;
    private static readonly UTF8Encoding Utf8 = new(false, true);

    public uint Unsigned() {
        if ((uint)Position >= (uint)data.Length)
            throw new InvalidDataException("Truncated NativeFormat integer.");

        int offset = Position;
        uint first = data[offset];
        if ((first & 1) == 0) {
            Position = offset + 1;
            return first >> 1;
        }

        int size = (first & 2) == 0 ? 2 : (first & 4) == 0 ? 3 : (first & 8) == 0 ? 4 : (first & 16) == 0 ? 5 : 0;
        if (size == 0 || size > data.Length - offset)
            throw new InvalidDataException($"Invalid NativeFormat integer at 0x{offset:X}.");

        uint result;
        if (size == 5)
            result = BinaryPrimitives.ReadUInt32LittleEndian(data[(offset + 1)..]);
        else {
            result = first >> size;
            int shift = 8 - size;
            for (int i = 1; i < size; ++i, shift += 8)
                result |= (uint)data[offset + i] << shift;
        }

        Position = offset + size;
        return result;
    }

    public int Signed() {
        int start = Position;
        uint value = Unsigned();
        int size = Position - start;
        if (size == 5)
            return unchecked((int)value);
        int shift = 32 - 7 * size;
        return unchecked((int)(value << shift)) >> shift;
    }

    public ulong UnsignedLong() {
        if ((uint)Position >= (uint)data.Length)
            throw new InvalidDataException("Truncated NativeFormat integer.");

        byte first = data[Position];
        if ((first & 31) != 31)
            return Unsigned();
        if ((first & 32) != 0 || data.Length - Position < 9)
            throw new InvalidDataException("Invalid 64-bit NativeFormat integer.");

        ulong value = BinaryPrimitives.ReadUInt64LittleEndian(data[(Position + 1)..]);
        Position += 9;
        return value;
    }

    public long SignedLong() {
        if ((uint)Position >= (uint)data.Length)
            throw new InvalidDataException("Truncated NativeFormat integer.");

        return (data[Position] & 31) == 31 ? unchecked((long)UnsignedLong()) : Signed();
    }

    public ReadOnlySpan<byte> Take(int count) {
        if (count < 0 || (uint)Position > (uint)data.Length || count > data.Length - Position)
            throw new InvalidDataException($"Truncated NativeFormat record at 0x{Position:X}.");

        var result = data.Slice(Position, count);
        Position += count;
        return result;
    }

    public string String() {
        int length = checked((int)Unsigned());
        return Utf8.GetString(Take(length));
    }
}

public ref struct NativeTable {
    private readonly ReadOnlySpan<byte> data;
    private readonly int indexSize;
    private readonly int bucketCount;
    private int bucket;
    private int position;
    private int end;
    public int Bucket { get; private set; }
    public readonly int BucketMask => bucketCount - 1;
    public byte LowHash { get; private set; }
    public int Vertex { get; private set; }

    public NativeTable(ReadOnlySpan<byte> bytes) {
        data = bytes;
        if (bytes.IsEmpty)
            return;
        int shift = bytes[0] >> 2;
        int sizeCode = bytes[0] & 3;
        if (shift > 29 || sizeCode > 2)
            throw new InvalidDataException("Invalid NativeHashtable header.");

        bucketCount = 1 << shift;
        indexSize = 1 << sizeCode;
        if (((long)bucketCount + 1) * indexSize > bytes.Length - 1)
            throw new InvalidDataException("Truncated NativeHashtable index.");

        int indexEnd = 1 + (bucketCount + 1) * indexSize;
        int previous = indexEnd;
        for (int i = 0; i <= bucketCount; ++i) {
            int boundary = Boundary(i);
            if (boundary < previous || boundary > bytes.Length)
                throw new InvalidDataException("NativeHashtable bucket exceeds storage or is out of order.");

            previous = boundary;
        }

        position = end = Boundary(0);
    }

    private readonly int Boundary(int index) {
        var row = data[(1 + index * indexSize)..];
        uint value = indexSize == 1 ? row[0] : indexSize == 2
            ? BinaryPrimitives.ReadUInt16LittleEndian(row) : BinaryPrimitives.ReadUInt32LittleEndian(row);
        return checked((int)value + 1);
    }

    public bool MoveNext() {
        while (position == end) {
            if (bucket == bucketCount)
                return false;
            Bucket = bucket++;
            end = Boundary(bucket);
            LowHash = 0;
        }

        byte hash = data[position++];
        if (hash < LowHash)
            throw new InvalidDataException("NativeHashtable hashes are out of runtime lookup order.");

        LowHash = hash;
        int origin = position;
        var reader = new NativeReader(data[..end], position);
        int delta = reader.Signed();
        long vertex = (long)origin + delta;
        if (vertex < 0 || vertex >= data.Length)
            throw new InvalidDataException("NativeHashtable vertex is outside storage.");

        Vertex = (int)vertex;
        position = reader.Position;
        return true;
    }
}
