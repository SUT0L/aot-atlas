using System.Buffers.Binary;
using System.Runtime.CompilerServices;

namespace Atlas;

public readonly struct HydratedRegion {
    public readonly ulong Start;
    internal readonly byte[] Storage;
    public readonly int Length;

    public HydratedRegion(ulong start, byte[] storage, int length)
        : this(start, storage, length, takeOwnership: false) {
    }

    internal HydratedRegion(ulong start, byte[] storage, int length, bool takeOwnership) {
        ArgumentNullException.ThrowIfNull(storage);
        ArgumentOutOfRangeException.ThrowIfNegative(length);
        ArgumentOutOfRangeException.ThrowIfGreaterThan(length, storage.Length);

        Start = start;
        Storage = takeOwnership ? storage : storage.AsSpan(0, length).ToArray();
        Length = length;
    }

    public ReadOnlySpan<byte> Bytes => Storage.AsSpan(0, Length);
}

public static class Hydration {
    public static HydratedRegion Read(PeImage image, ReadyToRun rtr, CancellationToken cancellationToken = default) {
        cancellationToken.ThrowIfCancellationRequested();
        rtr = rtr.ValidateSource(image);

        var section = rtr.Find(RtrSectionId.DehydratedData);
        if (section.Length == 0)
            return default;

        var range = image.FileRange(section.Start);
        if (section.Length > (ulong)range.Count)
            throw new InvalidDataException("Dehydrated data exceeds file-backed storage.");

        var backing = image.FileData.AsSpan(range.Start, range.Count);
        var encoded = backing[..(int)section.Length];
        if (encoded.Length < (rtr.EmbeddedDehydrationLength ? 8 : 4))
            throw new InvalidDataException("Truncated dehydrated data header.");

        ulong destination = checked((ulong)(
            (long)section.Start + BinaryPrimitives.ReadInt32LittleEndian(encoded)));
        int destinationSection = image.FindSection(destination);

        if (destinationSection < 0 || !image.Sections[destinationSection].Writable)
            throw new InvalidDataException("Dehydration destination is not mapped writable storage.");

        ref readonly var target = ref image.Sections[destinationSection];
        ulong capacity = target.VirtualSize - (destination - image.ImageBase - target.Rva);

        int position = rtr.EmbeddedDehydrationLength ? 8 : 4;
        int commandEnd = rtr.EmbeddedDehydrationLength
            ? BinaryPrimitives.ReadInt32LittleEndian(encoded[4..])
            : encoded.Length;

        if (commandEnd < position || commandEnd > encoded.Length)
            throw new InvalidDataException("Dehydrated command length exceeds its RTR section.");

        var commands = encoded[..commandEnd];

        ulong fixupBase = section.Start + (uint)commandEnd;
        // Legacy rows exclude the lookup table, but both formats keep it in the command stream's region.
        var fixups = rtr.EmbeddedDehydrationLength ? encoded[commandEnd..] : backing[commandEnd..];

        // Validate every relocation and output extent before acquiring destination storage.
        int length = Process(
            commands, position, fixups, section.Start, fixupBase, destination,
            default, capacity, write: false, cancellationToken);

        // The decoder writes every byte, including the zero-fill commands.
        byte[] storage = GC.AllocateUninitializedArray<byte>(length);
        int expanded = Expand(commands, position, fixups, section.Start, fixupBase, destination, storage, cancellationToken);
        System.Diagnostics.Debug.Assert(expanded == length);

        return new HydratedRegion(destination, storage, length, takeOwnership: true);
    }

    public static int Expand(
        ReadOnlySpan<byte> commands,
        int position,
        ReadOnlySpan<byte> fixups,
        ulong commandBase,
        ulong fixupBase,
        ulong destination,
        Span<byte> output,
        CancellationToken cancellationToken = default)
        => Process(
            commands, position, fixups, commandBase, fixupBase, destination,
            output, (uint)output.Length, write: true, cancellationToken);

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static int Process(
        ReadOnlySpan<byte> commands,
        int position,
        ReadOnlySpan<byte> fixups,
        ulong commandBase,
        ulong fixupBase,
        ulong destination,
        Span<byte> output,
        ulong capacity,
        bool write,
        CancellationToken cancellationToken) {
        cancellationToken.ThrowIfCancellationRequested();

        if ((uint)position > (uint)commands.Length)
            throw new InvalidDataException("Dehydrated command offset exceeds storage.");

        int written = 0;

        while (position < commands.Length) {
            cancellationToken.ThrowIfCancellationRequested();

            var (opcode, payload, inputSize, outputSize) = ReadCommand(commands, ref position);

            if ((ulong)written + (uint)outputSize > capacity
                || outputSize > Array.MaxLength - written)
                throw new InvalidDataException("Dehydrated command exceeds destination storage.");

            var dest = write ? output.Slice(written, outputSize) : default;

            switch (opcode) {
                case 0:
                    if (write)
                        commands.Slice(position, payload).CopyTo(dest);
                    break;

                case 1:
                    if (write)
                        dest.Clear();
                    break;

                case 2:
                case 3: {
                    long fixupOffset = (long)payload * 4;
                    if (fixupOffset > fixups.Length - 4)
                        throw new InvalidDataException("Dehydrated relocation is outside the fixup table.");

                    long value = checked((long)fixupBase + fixupOffset
                        + BinaryPrimitives.ReadInt32LittleEndian(fixups[(int)fixupOffset..]));

                    if (opcode == 3) {
                        ulong absolute = checked((ulong)value);

                        if (write)
                            BinaryPrimitives.WriteUInt64LittleEndian(dest, absolute);
                    } else {
                        int relative = checked((int)(value - (long)destination - written));

                        if (write)
                            BinaryPrimitives.WriteInt32LittleEndian(dest, relative);
                    }

                    break;
                }

                case 4:
                case 5: {
                    int stride = opcode == 5 ? 8 : 4;
                    var source = commands.Slice(position, inputSize);

                    for (int i = 0, offset = 0; i < inputSize; i += 4, offset += stride) {
                        if ((i & 4095) == 0)
                            cancellationToken.ThrowIfCancellationRequested();

                        long value = checked((long)commandBase + position + i
                            + BinaryPrimitives.ReadInt32LittleEndian(source[i..]));

                        if (stride == 8) {
                            ulong absolute = checked((ulong)value);

                            if (write)
                                BinaryPrimitives.WriteUInt64LittleEndian(dest[offset..], absolute);
                        } else {
                            int relative = checked((int)(value - (long)destination - written - offset));

                            if (write)
                                BinaryPrimitives.WriteInt32LittleEndian(dest[offset..], relative);
                        }
                    }

                    break;
                }
            }

            written += outputSize;
            position += inputSize;
        }

        return written;
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static (int Opcode, int Payload, int InputSize, int OutputSize) ReadCommand(
        ReadOnlySpan<byte> commands,
        ref int position) {
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

        if (inputSize > commands.Length - position)
            throw new InvalidDataException("Dehydrated command exceeds source storage.");

        return (opcode, payload, inputSize, outputSize);
    }
}
