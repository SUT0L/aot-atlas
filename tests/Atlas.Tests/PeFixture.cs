using System.Buffers.Binary;
using Atlas;

internal static class PeFixture {
    internal static PeImage Create(byte[] data, string section, uint flags) {
        byte[] bytes = new byte[512 + data.Length];
        "MZ"u8.CopyTo(bytes);
        BinaryPrimitives.WriteUInt32LittleEndian(bytes.AsSpan(60), 64);
        "PE\0\0"u8.CopyTo(bytes.AsSpan(64));
        BinaryPrimitives.WriteUInt16LittleEndian(bytes.AsSpan(68), 0x8664);
        BinaryPrimitives.WriteUInt16LittleEndian(bytes.AsSpan(70), 1);
        BinaryPrimitives.WriteUInt16LittleEndian(bytes.AsSpan(84), 240);
        BinaryPrimitives.WriteUInt16LittleEndian(bytes.AsSpan(88), 0x20B);
        BinaryPrimitives.WriteUInt64LittleEndian(bytes.AsSpan(112), 0x140000000);
        BinaryPrimitives.WriteUInt32LittleEndian(bytes.AsSpan(144), 0x1000 + (uint)data.Length);
        BinaryPrimitives.WriteUInt32LittleEndian(bytes.AsSpan(148), 512);
        System.Text.Encoding.ASCII.GetBytes(section).CopyTo(bytes.AsSpan(328));
        BinaryPrimitives.WriteUInt32LittleEndian(bytes.AsSpan(336), (uint)data.Length);
        BinaryPrimitives.WriteUInt32LittleEndian(bytes.AsSpan(340), 0x1000);
        BinaryPrimitives.WriteUInt32LittleEndian(bytes.AsSpan(344), (uint)data.Length);
        BinaryPrimitives.WriteUInt32LittleEndian(bytes.AsSpan(348), 512);
        BinaryPrimitives.WriteUInt32LittleEndian(bytes.AsSpan(364), flags);
        data.CopyTo(bytes.AsSpan(512));
        return new PeImage(bytes);
    }
}
