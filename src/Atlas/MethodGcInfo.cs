using System.Numerics;
using System.Runtime.CompilerServices;

namespace Atlas;

public readonly record struct MethodGcSlot(int Register, int StackBase, int StackOffset, byte Flags);
public readonly record struct MethodGcRange(uint Start, uint End);
public readonly record struct MethodGcTransition(uint Offset, int Slot, bool Live, bool ChunkStart = false);

// AMD64 NativeAOT GCINFO versions 2–5. Version 5 changes only the x86 encoding.
public sealed class MethodGcInfo {
    public ushort Flags { get; internal set; }
    public uint CodeLength { get; internal set; }
    public uint OutgoingStackBytes { get; internal set; }

    public uint ValidRangeStart { get; internal set; }
    public uint ValidRangeEnd { get; internal set; }
    public uint EditAndContinueBytes { get; internal set; }
    public int ReturnKind { get; internal set; } = -1;

    public int SecurityObjectSlot { get; internal set; } = -1;
    public int StackBaseRegister { get; internal set; } = -1;
    public int CookieSlot { get; internal set; } = -1;
    public int PspSlot { get; internal set; } = -1;
    public int GenericContextSlot { get; internal set; } = -1;
    public int ReversePInvokeSlot { get; internal set; } = -1;

    internal MethodGcSlot[] Slots = [];
    internal uint[] SafePoints = [];
    internal MethodGcRange[] Ranges = [];
    internal IndexRange[][] LiveSlotRuns = [];
    internal MethodGcTransition[] Transitions = [];
    public int HeaderBytes { get; internal set; }
    public ReadOnlySpan<MethodGcSlot> SlotEntries => Slots;
    public ReadOnlySpan<uint> SafePointOffsets => SafePoints;
    public ReadOnlySpan<MethodGcRange> InterruptibleRanges => Ranges;
    public ReadOnlySpan<MethodGcTransition> TransitionEntries => Transitions;
    public ReadOnlySpan<IndexRange> LiveSlotsAt(int safePoint) => LiveSlotRuns[safePoint];

    public static MethodGcInfo Read(ReadOnlySpan<byte> data, int version = 4,
        CancellationToken cancellationToken = default) {
        cancellationToken.ThrowIfCancellationRequested();
        try {
            if (version is < 2 or > 5)
                throw new NotSupportedException($"Unsupported AMD64 GC info version {version}.");

            var result = ReadCore(data, version, cancellationToken);
            cancellationToken.ThrowIfCancellationRequested();
            return result;
        } catch (OverflowException error) {
            throw new InvalidDataException("GC encoding exceeds supported numeric bounds.", error);
        }
    }

    private static MethodGcInfo ReadCore(ReadOnlySpan<byte> data, int version, CancellationToken cancellationToken) {
        var bits = new GcBits(data);
        bool slim = bits.Read(1) == 0;
        var result = new MethodGcInfo {
            Flags = (ushort)(slim ? bits.Read(1) * 64 : bits.Read(10))
        };
        uint flags = result.Flags;

        if (version >= 4 && (flags & 0xA) != 0)
            throw new InvalidDataException($"Reserved GCINFO v{version} header flags 0x{flags & 0xA:X}.");

        if (version < 4)
            result.ReturnKind = (int)bits.Read(slim ? 2 : 4);

        result.CodeLength = bits.Unsigned(8);
        if (result.CodeLength == 0)
            throw new InvalidDataException("Empty GC method code range.");

        if ((flags & 4) != 0) {
            result.ValidRangeStart = checked(bits.Unsigned(5) + 1);
            uint epilogSize = bits.Unsigned(3);

            if (epilogSize > result.CodeLength || result.ValidRangeStart >= result.CodeLength - epilogSize)
                throw new InvalidDataException("GC cookie validity range is outside its method.");

            result.ValidRangeEnd = result.CodeLength - epilogSize;
        } else if ((flags & 0x32) != 0) {
            result.ValidRangeStart = checked(bits.Unsigned(5) + 1);
            result.ValidRangeEnd = checked(result.ValidRangeStart + 1);

            if (result.ValidRangeStart >= result.CodeLength)
                throw new InvalidDataException("GC generic context validity start is outside its method.");
        }

        if ((flags & 2) != 0)
            result.SecurityObjectSlot = checked(bits.Signed(6) * 8);

        if ((flags & 4) != 0)
            result.CookieSlot = checked(bits.Signed(6) * 8);

        if ((flags & 8) != 0)
            result.PspSlot = checked(bits.Signed(6) * 8);

        if ((flags & 0x30) != 0)
            result.GenericContextSlot = checked(bits.Signed(6) * 8);

        if ((flags & 64) != 0)
            result.StackBaseRegister = slim ? 5 : checked((int)bits.Unsigned(3) ^ 5);

        if (result.StackBaseRegister > 15)
            throw new InvalidDataException("GC stack-base register is invalid for AMD64.");

        if ((flags & 0x100) != 0)
            result.EditAndContinueBytes = bits.Unsigned(4);

        if ((flags & 0x200) != 0)
            result.ReversePInvokeSlot = checked(bits.Signed(6) * 8);

        if (!slim)
            result.OutgoingStackBytes = checked(bits.Unsigned(3) * 8);

        int safeCount = bits.Count(2);
        int rangeCount = slim ? 0 : bits.Count(1);

        if (safeCount != 0 && rangeCount != 0)
            throw new InvalidDataException("GC safe points and interruptible ranges are mutually exclusive.");

        if (safeCount > result.CodeLength
            || safeCount > (long)data.Length * 8
            || rangeCount > (long)data.Length * 4)
            throw new InvalidDataException("GC method point/range count exceeds storage.");

        int offsetBits = result.CodeLength == 1 ? 0 : BitOperations.Log2(result.CodeLength - 1) + 1;
        if ((long)safeCount * offsetBits > bits.Remaining)
            throw new InvalidDataException("GC safe point table exceeds storage.");

        result.SafePoints = new uint[safeCount];

        for (int i = 0; i < safeCount; ++i) {
            cancellationToken.ThrowIfCancellationRequested();
            uint offset = bits.Read(offsetBits);
            if (offset >= result.CodeLength)
                throw new InvalidDataException("GC safe point is outside its method.");

            // Older encoders store call-return PCs minus one. Publish the actual PCs.
            if (version < 4)
                ++offset;

            if (i > 0 && offset <= result.SafePoints[i - 1])
                throw new InvalidDataException("GC safe points are not strictly ordered.");

            result.SafePoints[i] = offset;
        }

        if ((long)rangeCount * 14 > bits.Remaining)
            throw new InvalidDataException("GC interruptible range table exceeds storage.");

        result.Ranges = new MethodGcRange[rangeCount];
        uint previousEnd = 0;

        for (int i = 0; i < rangeCount; ++i) {
            cancellationToken.ThrowIfCancellationRequested();
            uint start = checked(previousEnd + bits.Unsigned(6));
            uint end = checked(start + bits.Unsigned(6) + 1);

            if (end > result.CodeLength)
                throw new InvalidDataException("GC interruptible range is outside its method.");

            result.Ranges[i] = new MethodGcRange(start, end);
            previousEnd = end;
        }

        int registers = bits.Read(1) == 0 ? 0 : bits.Count(2);
        int tracked = 0;
        int untracked = 0;

        if (bits.Read(1) != 0) {
            tracked = bits.Count(2);
            untracked = bits.Count(1);
        }

        int total = checked(registers + tracked + untracked);
        if (total > (long)data.Length * 8)
            throw new InvalidDataException("GC slot count exceeds storage.");

        if ((long)registers * 3 + ((long)tracked + untracked) * 7 > bits.Remaining)
            throw new InvalidDataException("GC slot table exceeds storage.");

        result.Slots = new MethodGcSlot[total];
        int cursor = 0;
        int register = 0;
        byte slotFlags = 1;

        for (int i = 0; i < registers; ++i) {
            cancellationToken.ThrowIfCancellationRequested();

            if (slotFlags != 0) {
                register = checked((int)bits.Unsigned(3));
                slotFlags = (byte)bits.Read(2);
            } else {
                register = checked(register + (int)bits.Unsigned(2) + 1);
            }

            if (register >= 16 || register == 4)
                throw new InvalidDataException("GC slot has an invalid AMD64 register.");

            result.Slots[cursor++] = new MethodGcSlot(register, -1, 0, slotFlags);
        }

        for (int group = 0; group < 2; ++group) {
            int count = group == 0 ? tracked : untracked;
            int stackOffset = 0;
            slotFlags = 1;

            for (int i = 0; i < count; ++i) {
                cancellationToken.ThrowIfCancellationRequested();
                int stackBase = (int)bits.Read(2);
                if (stackBase > 2)
                    throw new InvalidDataException("GC slot has an invalid stack base.");

                if (stackBase == 2 && result.StackBaseRegister is -1 or 4)
                    throw new InvalidDataException("GC frame-relative slot has no usable frame register.");

                if (slotFlags != 0) {
                    stackOffset = bits.Signed(6);
                    slotFlags = (byte)bits.Read(2);
                } else {
                    stackOffset = checked(stackOffset + bits.Signed(4));
                }

                result.Slots[cursor++] = new MethodGcSlot(
                    -1, stackBase, checked(stackOffset * 8),
                    (byte)(slotFlags | (group == 1 ? 4 : 0)));
            }
        }

        result.HeaderBytes = (bits.Position + 7) / 8;
        int trackedCount = registers + tracked;

        if (trackedCount == 0)
            return result;

        if (safeCount == 0) {
            if (rangeCount == 0)
                return result;

            result.Transitions = ReadTransitions(
                ref bits, trackedCount, result.CodeLength, result.Ranges, cancellationToken);

            return result;
        }

        int pointerBits = bits.Read(1) == 0 ? 0 : checked(bits.Count(3) + 1);
        int tableStart = bits.Position;
        int stateStart = checked((tableStart + safeCount * pointerBits + 7) & ~7);

        result.LiveSlotRuns = new IndexRange[safeCount][];
        var live = new List<IndexRange>();
        var sharedStates = pointerBits == 0 ? null : new Dictionary<int, IndexRange[]>();

        for (int point = 0; point < safeCount; ++point) {
            cancellationToken.ThrowIfCancellationRequested();
            live.Clear();
            bool rle = false;

            if (pointerBits == 0) {
                bits.Position = checked(tableStart + point * trackedCount);
            } else {
                bits.Position = checked(tableStart + point * pointerBits);
                int offset = checked((int)bits.Read(pointerBits));
                bits.Position = checked(stateStart + offset);

                if (sharedStates!.TryGetValue(bits.Position, out var state)) {
                    result.LiveSlotRuns[point] = state;
                    continue;
                }

                rle = bits.Read(1) != 0;
            }

            int statePosition = pointerBits == 0 ? -1 : bits.Position - 1;
            result.LiveSlotRuns[point] = ReadLiveRuns(ref bits, trackedCount, rle, live, cancellationToken);

            if (sharedStates is not null)
                sharedStates.Add(statePosition, result.LiveSlotRuns[point]);
        }

        return result;
    }

    private static IndexRange[] ReadLiveRuns(
        ref GcBits bits,
        int trackedCount,
        bool rle,
        List<IndexRange> live,
        CancellationToken cancellationToken) {
        live.Clear();

        if (rle) {
            bool skip = bits.Read(1) == 0;
            int index = bits.Count(skip ? 4 : 2);
            skip = !skip;
            bool report = true;

            if (index > trackedCount)
                throw new InvalidDataException("GC liveness run exceeds tracked slots.");

            while (index < trackedCount) {
                cancellationToken.ThrowIfCancellationRequested();
                int count = checked(bits.Count(skip ? 4 : 2) + 1);
                if (count > trackedCount - index)
                    throw new InvalidDataException("GC liveness run exceeds tracked slots.");

                if (report)
                    live.Add(new IndexRange(index, count));

                index += count;
                skip = !skip;
                report = !report;
            }
        } else {
            int start = -1;

            for (int slot = 0; slot < trackedCount; ++slot) {
                cancellationToken.ThrowIfCancellationRequested();
                bool report = bits.Read(1) != 0;
                if (report && start < 0)
                    start = slot;
                else if (!report && start >= 0) {
                    live.Add(new IndexRange(start, slot - start));
                    start = -1;
                }
            }

            if (start >= 0)
                live.Add(new IndexRange(start, trackedCount - start));
        }

        return live.ToArray();
    }

    private static MethodGcTransition[] ReadTransitions(
        ref GcBits bits,
        int trackedCount,
        uint codeLength,
        MethodGcRange[] ranges,
        CancellationToken cancellationToken) {
        uint interruptibleLength = codeLength;

        if (ranges.Length != 0) {
            interruptibleLength = 0;

            foreach (var range in ranges) {
                cancellationToken.ThrowIfCancellationRequested();
                interruptibleLength = checked(interruptibleLength + range.End - range.Start);
            }
        }

        int chunkCount = checked((int)(((ulong)interruptibleLength + 63) / 64));
        int pointerBits = bits.Count(3);

        if (pointerBits == 0)
            return [];

        if (pointerBits > 32 || (long)chunkCount * pointerBits > bits.Remaining)
            throw new InvalidDataException("GC chunk pointer table exceeds storage.");

        int tableStart = bits.Position;
        int statesStart = checked((tableStart + chunkCount * pointerBits + 7) & ~7);

        var liveAtEnd = new bool[trackedCount];
        var live = new List<IndexRange>();
        var transitions = new List<MethodGcTransition>();
        var offsets = new List<uint>();

        for (int chunk = 0; chunk < chunkCount; ++chunk) {
            cancellationToken.ThrowIfCancellationRequested();
            bits.Position = checked(tableStart + chunk * pointerBits);
            uint pointer = bits.Read(pointerBits);

            if (pointer == 0)
                continue;

            bits.Position = checked(statesStart + (int)pointer - 1);
            bool rle = bits.Read(1) != 0;
            var slots = ReadLiveRuns(ref bits, trackedCount, rle, live, cancellationToken);

            if (slots.Length == 0)
                throw new InvalidDataException("GC chunk has no changing slots.");

            var finalStates = bits;
            int count = 0;

            foreach (var run in slots) {
                cancellationToken.ThrowIfCancellationRequested();
                count = checked(count + run.Count);
            }

            bits.Position = checked(bits.Position + count);

            foreach (var run in slots) {
                for (int slot = run.Start; slot < run.Start + run.Count; ++slot) {
                    cancellationToken.ThrowIfCancellationRequested();
                    offsets.Clear();
                    bool finalState = finalStates.Read(1) != 0;
                    int previousOffset = 0;

                    while (bits.Read(1) != 0) {
                        cancellationToken.ThrowIfCancellationRequested();
                        int offset = (int)bits.Read(6);
                        if (offset <= previousOffset)
                            throw new InvalidDataException(
                                "GC slot transitions are not strictly ordered or have a zero chunk offset.");

                        previousOffset = offset;
                        uint logicalOffset = checked((uint)chunk * 64 + (uint)offset);

                        if (logicalOffset >= interruptibleLength)
                            throw new InvalidDataException("GC transition is outside interruptible storage.");

                        offsets.Add(logicalOffset);
                    }

                    // Chunk-offset-zero transitions are omitted. Final-state parity
                    // determines the initial state without borrowing the previous chunk.
                    bool state = finalState ^ ((offsets.Count & 1) != 0);

                    if (state != liveAtEnd[slot])
                        transitions.Add(new(
                            PhysicalOffset((uint)chunk * 64, ranges, cancellationToken), slot, state,
                            ChunkStart: true));

                    foreach (uint offset in offsets) {
                        cancellationToken.ThrowIfCancellationRequested();
                        state = !state;
                        transitions.Add(new(PhysicalOffset(offset, ranges, cancellationToken), slot, state));
                    }

                    liveAtEnd[slot] = finalState;
                }
            }
        }

        cancellationToken.ThrowIfCancellationRequested();
        // A stable slot order keeps simultaneous transitions deterministic.
        transitions.Sort(static (left, right) => {
            int order = left.Offset.CompareTo(right.Offset);
            return order == 0 ? left.Slot.CompareTo(right.Slot) : order;
        });

        cancellationToken.ThrowIfCancellationRequested();
        return transitions.ToArray();
    }

    private static uint PhysicalOffset(uint offset, MethodGcRange[] ranges, CancellationToken cancellationToken) {
        foreach (var range in ranges) {
            cancellationToken.ThrowIfCancellationRequested();
            uint length = range.End - range.Start;

            if (offset < length)
                return checked(offset + range.Start);

            offset -= length;
        }

        return offset;
    }

    private ref struct GcBits {
        private readonly ReadOnlySpan<byte> bytes;
        public int Position;
        public long Remaining => (long)bytes.Length * 8 - Position;

        public GcBits(ReadOnlySpan<byte> bytes) {
            this.bytes = bytes;
            Position = 0;
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public uint Read(int count) {
            if (count < 0 || count > 32 || Position < 0 || (long)Position + count > (long)bytes.Length * 8)
                throw new InvalidDataException("Truncated or invalid GC bit stream.");

            if (count == 0)
                return 0;

            int first = Position >> 3;
            int shift = Position & 7;
            uint value = (uint)(bytes[first] >> shift);

            for (int taken = 8 - shift; taken < count; taken += 8)
                value |= (uint)bytes[++first] << taken;

            Position = checked(Position + count);

            return value & (uint.MaxValue >> (32 - count));
        }

        public uint Unsigned(int width) {
            ulong value = 0;

            for (int shift = 0; shift < 32; shift += width) {
                uint chunk = Read(width + 1);
                value |= (ulong)(chunk & ((1U << width) - 1)) << shift;

                if ((chunk & (1U << width)) == 0) {
                    if (value > uint.MaxValue)
                        throw new InvalidDataException("GC integer exceeds 32 bits.");

                    return (uint)value;
                }
            }

            throw new InvalidDataException("GC integer exceeds 32 bits.");
        }

        public int Signed(int width) {
            long value = 0;

            for (int shift = 0; shift < 32; shift += width) {
                uint chunk = Read(width + 1);
                value |= (long)(chunk & ((1U << width) - 1)) << shift;

                if ((chunk & (1U << width)) == 0) {
                    int used = shift + width;
                    if ((chunk & (1U << (width - 1))) != 0)
                        value -= 1L << used;

                    if (value < int.MinValue || value > int.MaxValue)
                        throw new InvalidDataException("GC signed integer exceeds 32 bits.");

                    return (int)value;
                }
            }

            throw new InvalidDataException("GC signed integer exceeds 32 bits.");
        }

        public int Count(int width) => checked((int)Unsigned(width));
    }
}
