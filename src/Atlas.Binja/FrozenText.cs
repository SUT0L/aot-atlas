using System.Buffers;
using System.Buffers.Binary;
using System.Buffers.Text;

namespace Atlas.Binja;

internal static class FrozenText {
    internal static int Quote(ReadOnlySpan<byte> data, Span<byte> output, bool wide = true) {
        int length = 0;
        output[length++] = (byte)'"';
        for (int i = 0; i < data.Length; i += wide ? 2 : 1) {
            ushort character = wide ? BinaryPrimitives.ReadUInt16LittleEndian(data[i..]) : data[i];
            if (character is (ushort)'"' or (ushort)'\\') {
                output[length++] = (byte)'\\';
                output[length++] = (byte)character;
            } else if (character is >= 0x20 and <= 0x7E) {
                output[length++] = (byte)character;
            } else {
                // A .NET string can contain lone surrogates
                // Escaping code units preserves them; a UTF-8 conversion would replace their values
                output[length++] = (byte)'\\';
                output[length++] = (byte)'u';
                Utf8Formatter.TryFormat(character, output[length..], out _, new StandardFormat('X', 4));
                length += 4;
            }
        }

        output[length++] = (byte)'"';
        return length;
    }
}
