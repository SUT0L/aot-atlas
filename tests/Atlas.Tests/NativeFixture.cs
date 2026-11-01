using System.Buffers.Binary;
using System.Text;

internal static class NativeFixture {
    internal static int Unsigned(byte[] data, int offset, params uint[] values) {
        foreach (uint value in values)
            offset = Number(data, offset, value, Width(value));
        return offset;
    }

    internal static int Signed(byte[] data, int offset, int value) {
        uint magnitude = value < 0 ? (uint)~value : (uint)value;
        int width = magnitude < 64 ? 1 : magnitude < 8192 ? 2
            : magnitude < 1048576 ? 3 : magnitude < 134217728 ? 4 : 5;
        return Number(data, offset, unchecked((uint)value), width);
    }

    internal static int Text(byte[] data, int offset, string value) {
        offset = Unsigned(data, offset, (uint)Encoding.UTF8.GetByteCount(value));
        return offset + Encoding.UTF8.GetBytes(value, data.AsSpan(offset));
    }

    private static int Width(uint value) => value < 128 ? 1 : value < 16384 ? 2
        : value < 2097152 ? 3 : value < 268435456 ? 4 : 5;

    private static int Number(byte[] data, int offset, uint value, int width) {
        if (width == 5) {
            data[offset] = 15;
            BinaryPrimitives.WriteUInt32LittleEndian(data.AsSpan(offset + 1), value);
            return offset + 5;
        }

        uint encoded = (value << width) | ((1U << (width - 1)) - 1);
        for (int i = 0; i < width; ++i)
            data[offset++] = (byte)(encoded >> (8 * i));
        return offset;
    }
}
