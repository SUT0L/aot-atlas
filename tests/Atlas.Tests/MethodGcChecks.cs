using Atlas;

internal static class MethodGcChecks {
    internal static void Run() {
        var lengthOne = MethodGcInfo.Read(Convert.FromHexString("0408"));
        Assert(lengthOne.CodeLength == 1 && lengthOne.SafePoints.SequenceEqual(new uint[] { 0 }),
            "Length-one safe points use zero offset bits.");

        var wide = new BitWriter();
        wide.Bits(0, 2);
        wide.Unsigned(uint.MaxValue, 8);
        wide.Unsigned(1, 2);
        wide.Bits(0xDEADBEEF, 32);
        wide.Bits(0, 2);

        var wideInfo = MethodGcInfo.Read(wide.Bytes());
        Assert(wideInfo.CodeLength == uint.MaxValue
            && wideInfo.SafePoints.SequenceEqual(new uint[] { 0xDEADBEEF }),
            "Unaligned 32-bit safe point offsets changed.");

        for (int count = 0; count < wide.Bytes().Length; ++count)
            Reject(wide.Bytes().AsSpan(0, count).ToArray());

        var liveRax = MethodGcInfo.Read(Convert.FromHexString("04C80004"));
        Assert(liveRax.Slots.Length == 1 && liveRax.LiveSlotRuns[0]
            .SelectMany(run => Enumerable.Range(run.Start, run.Count)).SequenceEqual(new[] { 0 }),
            "Length-one RAX liveness changed.");
        Reject(Convert.FromHexString("8180800200")); // Encoded stack-base register 21.
        Reject(Convert.FromHexString("40500E")); // Unsorted safe points 9,3.

        Reject(Convert.FromHexString("058030000000")); // Security-object flag is reserved in v4.
        Reject(Convert.FromHexString("1180000000")); // PSP flag is reserved in v4.
        Reject(Convert.FromHexString("2180F0000000")); // Generic context becomes valid after the method.
        Reject(Convert.FromHexString("018000402400")); // Frame-relative slot without a frame register.
        Reject(Convert.FromHexString("01800029008F0108")); // Contradictory liveness encodings.
        Reject(Convert.FromHexString("40C02000")); // RSP cannot contain a GC root.
        Reject(Convert.FromHexString("81801000440200")); // NativeAOT RegDisplay has no RSP register slot.

        foreach (int version in new[] { 2, 3 }) {
            foreach (bool slim in new[] { true, false }) {
                var old = new BitWriter();
                old.Bits(slim ? 0U : 1U, 1);
                old.Bits(0, slim ? 1 : 10);
                old.Bits(2, slim ? 2 : 4);
                old.Unsigned(16, 8);

                if (!slim)
                    old.Unsigned(0, 3);

                old.Unsigned(0, 2);

                if (!slim)
                    old.Unsigned(0, 1);

                old.Bits(0, 1);
                old.Bits(0, 1);

                var oldInfo = MethodGcInfo.Read(old.Bytes(), version);
                Assert(oldInfo.ReturnKind == 2 && oldInfo.CodeLength == 16 && oldInfo.Slots.Length == 0,
                    $"GCINFO v{version} {(slim ? "slim" : "fat")} header changed.");
            }
        }

        var noRanges = MethodGcInfo.Read(Full(128, [], [new(true, []), new(true, [])]));
        Assert(noRanges.Slots.Length == 1 && noRanges.Transitions.Length == 0,
            "No interruptible ranges must not invent whole-method tracked liveness.");

        foreach (int version in new[] { 2, 3 }) {
            foreach (uint flags in new uint[] { 2, 8 }) {
                var oldFlags = new BitWriter();
                oldFlags.Bits(1, 1);
                oldFlags.Bits(flags, 10);
                oldFlags.Bits(0, 4);
                oldFlags.Unsigned(16, 8);

                if (flags == 2)
                    oldFlags.Unsigned(3, 5);

                oldFlags.Signed(-2, 6);
                oldFlags.Unsigned(0, 3);
                oldFlags.Unsigned(0, 2);
                oldFlags.Unsigned(0, 1);
                oldFlags.Bits(0, 2);

                var oldInfo = MethodGcInfo.Read(oldFlags.Bytes(), version);
                Assert(flags == 2 ? oldInfo.SecurityObjectSlot == -16 && oldInfo.ValidRangeStart == 4
                    : oldInfo.PspSlot == -16, "Old security/PSP payload compatibility changed.");
            }

            var oldPoints = new BitWriter();
            oldPoints.Bits(0, 2);
            oldPoints.Bits(0, 2);
            oldPoints.Unsigned(16, 8);
            oldPoints.Unsigned(2, 2);
            oldPoints.Bits(0, 4);
            oldPoints.Bits(15, 4);
            oldPoints.Bits(0, 2);

            Assert(MethodGcInfo.Read(oldPoints.Bytes(), version).SafePoints.SequenceEqual(new uint[] { 1, 16 }),
                "Old safe points must report actual call-return PCs, including the method-end boundary.");
        }

        var boundary = Full(128, [new(0, 128)], [new(true, [8, 12]), new(true, [16])]);
        AssertTransitions(boundary, [
            new(0, 0, true, true),
            new(8, 0, false),
            new(12, 0, true),
            new(64, 0, false, true),
            new(80, 0, true)
        ]);

        // Encoder drops changes at chunk offset zero; final state reconstructs them.
        var initialOnly = Full(128, [new(0, 128)], [new(true, []), new(true, [])]);
        AssertTransitions(initialOnly, [new(0, 0, true, true)]);

        MethodGcRange[] gaps = [new(10, 15), new(30, 35), new(50, 60)];
        var crossing = Full(64, gaps, [new(true, [5, 12])]);
        AssertTransitions(crossing, [new(10, 0, true, true), new(30, 0, false), new(52, 0, true)]);

        // A transition at the end of one range belongs to the next range's start.
        Reject(Full(64, gaps, [new(true, [20])]));
        Reject(Full(64, gaps, [new(true, [0])]));
        Reject(Full(64, gaps, [new(true, [5, 5])]));
        Reject(Full(64, gaps, [new(true, [12, 5])]));

        for (int count = 0; count < crossing.Length; ++count)
            Reject(crossing.AsSpan(0, count).ToArray());

        var reverse = new BitWriter();
        reverse.Bits(1, 1);
        reverse.Bits(0x200, 10);
        reverse.Unsigned(16, 8);
        reverse.Signed(-2, 6);
        reverse.Unsigned(0, 3);
        reverse.Unsigned(0, 2);
        reverse.Unsigned(0, 1);
        reverse.Bits(0, 1);
        reverse.Bits(0, 1);

        Assert(MethodGcInfo.Read(reverse.Bytes()).ReversePInvokeSlot == -16,
            "Reverse-P/Invoke slot must be a byte offset.");

        var cookie = new BitWriter();
        cookie.Bits(1, 1);
        cookie.Bits(4, 10);
        cookie.Unsigned(16, 8);
        cookie.Unsigned(3, 5);
        cookie.Unsigned(2, 3);
        cookie.Signed(-2, 6);
        cookie.Unsigned(0, 3);
        cookie.Unsigned(0, 2);
        cookie.Unsigned(0, 1);
        cookie.Bits(0, 1);
        cookie.Bits(0, 1);

        var cookieInfo = MethodGcInfo.Read(cookie.Bytes());
        Assert(cookieInfo.CookieSlot == -16 && cookieInfo.ValidRangeStart == 4 && cookieInfo.ValidRangeEnd == 14,
            "GC cookie validity or slot units changed.");

        var emptyCookie = new BitWriter();
        emptyCookie.Bits(1, 1);
        emptyCookie.Bits(4, 10);
        emptyCookie.Unsigned(16, 8);
        emptyCookie.Unsigned(13, 5);
        emptyCookie.Unsigned(2, 3);
        emptyCookie.Signed(0, 6);
        emptyCookie.Unsigned(0, 3);
        emptyCookie.Unsigned(0, 2);
        emptyCookie.Unsigned(0, 1);
        emptyCookie.Bits(0, 1);
        emptyCookie.Bits(0, 1);

        Reject(emptyCookie.Bytes());

        byte[] dense = DenseSafePoints(128, 8192);
        MethodGcInfo.Read(dense); // Exclude first-use JIT allocations from the measured decoder.
        long allocated = GC.GetAllocatedBytesForCurrentThread();

        var denseInfo = MethodGcInfo.Read(dense);
        allocated = GC.GetAllocatedBytesForCurrentThread() - allocated;
        Assert(denseInfo.LiveSlotRuns.Length == 128 && denseInfo.LiveSlotRuns.All(runs =>
            runs.Length == 1 && runs[0].Start == 0 && runs[0].Count == 8192),
            "Dense RLE live-slot masks changed.");
        Assert(allocated < 1_000_000,
            $"Dense RLE masks expanded into retained per-slot arrays: {allocated} allocated bytes for {dense.Length} encoded bytes.");

        Console.WriteLine($"Method GC dense RLE: {dense.Length} encoded bytes, 1048576 live-slot references, {allocated} decoder allocation bytes.");

        var random = new Random(92831);

        for (int i = 0; i < 10_000; ++i) {
            byte[] bytes = new byte[random.Next(1, 128)];
            random.NextBytes(bytes);

            try {
                MethodGcInfo.Read(bytes);
            } catch (InvalidDataException) { }
        }

        Console.WriteLine("Method GC: length-one safepoints, chunk-boundary state, multi-gap PCs, offset bounds/order, slot units, old-version call-return PCs, reserved flags, missing frame registers, incompatible liveness modes, truncations and 10000 seeded malformed blobs passed.");
    }

    private static void AssertTransitions(byte[] blob, MethodGcTransition[] expected) {
        var info = MethodGcInfo.Read(blob);
        Assert(info.Transitions.SequenceEqual(expected),
            $"Full GC transitions differ for {Convert.ToHexString(blob)}: {string.Join(',', info.Transitions)}.");
    }

    private readonly record struct Chunk(bool FinalState, uint[] Offsets);

    private static byte[] Full(uint length, MethodGcRange[] ranges, Chunk[] chunks) {
        var header = new BitWriter();
        header.Bits(1, 1);
        header.Bits(0, 10);
        header.Unsigned(length, 8);
        header.Unsigned(0, 3);
        header.Unsigned(0, 2);
        header.Unsigned((uint)ranges.Length, 1);
        uint previousEnd = 0;

        foreach (var range in ranges) {
            header.Unsigned(range.Start - previousEnd, 6);
            header.Unsigned(range.End - range.Start - 1, 6);
            previousEnd = range.End;
        }

        header.Bits(1, 1);
        header.Unsigned(1, 2);
        header.Bits(0, 1);
        header.Unsigned(0, 3);
        header.Bits(0, 2); // One tracked RAX object reference.

        var states = new BitWriter();
        var pointers = new List<uint>();

        foreach (var chunk in chunks) {
            pointers.Add((uint)states.Count + 1);
            states.Bits(0, 1);
            states.Bits(1, 1);
            states.Bits(chunk.FinalState ? 1U : 0U, 1);

            foreach (uint offset in chunk.Offsets) {
                states.Bits(1, 1);
                states.Bits(offset, 6);
            }

            states.Bits(0, 1);
        }

        int pointerWidth = 1;

        while ((1UL << pointerWidth) <= pointers.Max())
            ++pointerWidth;

        header.Unsigned((uint)pointerWidth, 3);

        foreach (uint pointer in pointers)
            header.Bits(pointer, pointerWidth);

        header.Align();
        header.Append(states);
        return header.Bytes();
    }

    private static byte[] DenseSafePoints(int pointCount, int slotCount) {
        var header = new BitWriter();
        header.Bits(1, 1);
        header.Bits(0, 10);
        header.Unsigned(256, 8);
        header.Unsigned(0, 3);
        header.Unsigned((uint)pointCount, 2);
        header.Unsigned(0, 1);

        for (int point = 0; point < pointCount; ++point)
            header.Bits((uint)point, 8);

        header.Bits(0, 1);
        header.Bits(1, 1);
        header.Unsigned((uint)slotCount, 2);
        header.Unsigned(0, 1);

        for (int slot = 0; slot < slotCount; ++slot) {
            header.Bits(0, 2);
            header.Signed(0, slot == 0 ? 6 : 4);

            if (slot == 0)
                header.Bits(0, 2);
        }

        var states = new BitWriter();
        var pointers = new List<uint>();

        for (int point = 0; point < pointCount; ++point) {
            pointers.Add((uint)states.Count);
            states.Bits(1, 1);
            states.Bits(0, 1);
            states.Unsigned(0, 4);
            states.Unsigned((uint)slotCount - 1, 2);
        }

        int width = 1;

        while ((1UL << width) <= pointers.Max())
            ++width;

        header.Bits(1, 1);
        header.Unsigned((uint)width - 1, 3);

        foreach (uint pointer in pointers)
            header.Bits(pointer, width);

        header.Align();
        header.Append(states);
        return header.Bytes();
    }

    private sealed class BitWriter {
        private readonly List<byte> bits = [];

        internal int Count => bits.Count;

        internal void Bits(uint value, int count) {
            for (int i = 0; i < count; ++i)
                bits.Add((byte)((value >> i) & 1));
        }

        internal void Unsigned(uint value, int width) {
            uint mask = (1U << width) - 1;

            do {
                uint payload = value & mask;
                value >>= width;
                Bits(payload | (value == 0 ? 0U : 1U << width), width + 1);
            } while (value != 0);
        }

        internal void Signed(int value, int width) {
            int mask = (1 << width) - 1;

            while (true) {
                uint payload = (uint)(value & mask);
                value >>= width;
                bool negative = (payload & (1U << (width - 1))) != 0;
                bool last = negative ? value == -1 : value == 0;
                Bits(payload | (last ? 0U : 1U << width), width + 1);

                if (last)
                    return;
            }
        }

        internal void Align() {
            while ((Count & 7) != 0)
                bits.Add(0);
        }

        internal void Append(BitWriter value) {
            bits.AddRange(value.bits);
        }

        internal byte[] Bytes() {
            byte[] result = new byte[(Count + 7) / 8];

            for (int i = 0; i < Count; ++i)
                result[i / 8] |= (byte)(bits[i] << (i & 7));

            return result;
        }
    }

    private static void Reject(byte[] blob) {
        bool rejected = false;

        try {
            MethodGcInfo.Read(blob);
        } catch (InvalidDataException) {
            rejected = true;
        }

        Assert(rejected, $"Invalid GC encoding accepted: {Convert.ToHexString(blob)}.");
    }

    private static void Assert(bool condition, string message) {
        if (!condition)
            throw new Exception(message);
    }
}
