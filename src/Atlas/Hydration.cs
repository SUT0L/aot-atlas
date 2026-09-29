using System.Buffers.Binary;

namespace Atlas;

public readonly struct HydratedRegion(ulong start, byte[] storage, int length) {
    public readonly ulong Start = start;
    public readonly byte[] Storage = storage;
    public readonly int Length = length;
    public ReadOnlySpan<byte> Bytes => Storage.AsSpan(0, Length);
}

public static class Hydration {
    public static HydratedRegion Read(PeImage image, ReadyToRun rtr) {
        var section = rtr.Find(207);
        if (section.Length == 0)
            return default;
        var encoded = image.FileSpan(section.Start, checked((int)section.Length));
        if (encoded.Length < (rtr.EmbeddedDehydrationLength ? 8 : 4))
            throw new InvalidDataException("Truncated dehydrated data header.");

        ulong destination = checked((ulong)((long)section.Start + BinaryPrimitives.ReadInt32LittleEndian(encoded)));
        int destinationSection = image.FindSection(destination);
        if (destinationSection < 0 || !image.Sections[destinationSection].Writable)
            throw new InvalidDataException("Dehydration destination is not mapped writable storage.");

        ref readonly var target = ref image.Sections[destinationSection];
        ulong capacity = target.VirtualSize - (destination - image.ImageBase - target.Rva);
        int position = rtr.EmbeddedDehydrationLength ? 8 : 4;
        int commandEnd = rtr.EmbeddedDehydrationLength
            ? BinaryPrimitives.ReadInt32LittleEndian(encoded[4..]) : encoded.Length;
        if (commandEnd < position || commandEnd > encoded.Length)
            throw new InvalidDataException("Dehydrated command length exceeds its RTR section.");

        var commands = encoded[..commandEnd];
        ulong fixupBase = section.Start + (uint)commandEnd;
        int fixupSection = image.FindSection(fixupBase);
        if (fixupSection < 0)
            throw new InvalidDataException("Unmapped dehydration fixup table.");

        ref readonly var fixupPeSection = ref image.Sections[fixupSection];
        ulong available = (ulong)fixupPeSection.FileSize - (fixupBase - image.ImageBase - fixupPeSection.Rva);
        var fixups = rtr.EmbeddedDehydrationLength ? encoded[commandEnd..]
            : image.FileSpan(fixupBase, checked((int)available));
        // PE storage bounds the expansion
        // One zeroed allocation retains the runtimes zero-fill semantics without guessing a compression ratio
        byte[] storage = new byte[checked((int)capacity)];
        int length = Expand(commands, position, fixups, section.Start, fixupBase, destination, storage);
        return new HydratedRegion(destination, storage, length);
    }

    public static int Expand(ReadOnlySpan<byte> commands, int position, ReadOnlySpan<byte> fixups,
        ulong commandBase, ulong fixupBase, ulong destination, Span<byte> output) {
        int written = 0;
        while (position < commands.Length) {
            byte instruction = commands[position++];
            int opcode = instruction & 7;
            int payload = instruction >> 3;
            int extra = payload - 28;
            if (extra > 0) {
                if (extra > commands.Length - position)
                    throw new InvalidDataException("Truncated dehydrated command.");

                payload = 28 + commands[position++];
                if (extra > 1)
                    payload += commands[position++] << 8;
                if (extra > 2)
                    payload += commands[position++] << 16;
            }

            int outputSize = opcode switch {
                0 or 1 => payload,
                2 => 4,
                3 => 8,
                4 => checked(payload * 4),
                5 => checked(payload * 8),
                _ => throw new InvalidDataException($"Invalid dehydrated opcode {opcode}.")
            };
            int inputSize = opcode switch {
                0 => payload,
                4 or 5 => checked(payload * 4),
                _ => 0
            };
            if (inputSize > commands.Length - position || outputSize > output.Length - written)
                throw new InvalidDataException("Dehydrated command exceeds source or destination storage.");

            var dest = output.Slice(written, outputSize);
            switch (opcode) {
                case 0:
                    commands.Slice(position, payload).CopyTo(dest);
                    break;
                case 1:
                    dest.Clear();
                    break;
                case 2:
                case 3: {
                        long fixupOffset = (long)payload * 4;
                        if (fixupOffset > fixups.Length - 4)
                            throw new InvalidDataException("Dehydrated relocation is outside the fixup table.");

                        long value = checked((long)fixupBase + fixupOffset
                            + BinaryPrimitives.ReadInt32LittleEndian(fixups[(int)fixupOffset..]));
                        if (opcode == 3)
                            BinaryPrimitives.WriteUInt64LittleEndian(dest, checked((ulong)value));
                        else
                            BinaryPrimitives.WriteInt32LittleEndian(dest, checked((int)(value - (long)destination - written)));
                        break;
                    }
                case 4:
                case 5: {
                        int stride = opcode == 5 ? 8 : 4;
                        var source = commands.Slice(position, inputSize);
                        for (int i = 0, offset = 0; i < inputSize; i += 4, offset += stride) {
                            long value = checked((long)commandBase + position + i
                                + BinaryPrimitives.ReadInt32LittleEndian(source[i..]));
                            if (stride == 8)
                                BinaryPrimitives.WriteUInt64LittleEndian(dest[offset..], checked((ulong)value));
                            else
                                BinaryPrimitives.WriteInt32LittleEndian(dest[offset..], checked((int)(value - (long)destination - written - offset)));
                        }
                        break;
                    }
            }

            written += outputSize;
            position += inputSize;
        }

        return written;
    }
}
