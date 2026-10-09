using System.Numerics;
using Atlas;

internal static class GcTransitionOracleChecks {
    internal static void Run(string binary, int? expectedTransitions) {
        var image = new PeImage(File.ReadAllBytes(binary));
        var header = ReadyToRun.Read(image);
        Assert(header.Format.MethodGcVersion == 4, "Native transition oracle requires GCINFO v4.");

        var memory = new RuntimeMemory(image, Hydration.Read(image, header));
        var analysis = new UnwindAnalysis(image, header, memory);
        var map = new MethodGcMap(image, header, analysis.RequireUnwind(), analysis.RequireManaged());
        int transitions = 0;
        int full = 0;
        int chunkStarts = 0;

        foreach (var method in map.Methods) {
            Assert(method.Info is not null, $"Fixture GC header 0x{method.Address:X} is unavailable.");
            var info = method.Info!;
            var range = image.FileRange(image.ImageBase + method.Address);
            var expected = NativeModel(image.FileData.AsSpan(range.Start, range.Count).ToArray());
            var actual = info.Transitions.Select(value =>
                (value.Offset, value.Slot, value.Live, value.ChunkStart));

            Assert(actual.SequenceEqual(expected),
                $"Native transition model disagrees at method RVA 0x{method.Begin:X}.");
            transitions += expected.Length;
            chunkStarts += expected.Count(value => value.Item4);

            if (info.Ranges.Length != 0 && info.Slots.Any(slot => (slot.Flags & 4) == 0))
                ++full;
        }

        Assert(full > 0 && transitions > 0 && chunkStarts > 0,
            "Fixture must exercise full interruptibility, transitions and inferred chunk starts.");
        Assert(expectedTransitions is null || transitions == expectedTransitions,
            $"Native transition coverage changed: {transitions}.");
        Console.WriteLine($"Native GC transition oracle: {map.Methods.Length} roots, {full} fully interruptible methods, {transitions} transitions and {chunkStarts} inferred chunk starts agree.");
    }

    private static (uint Offset, int Slot, bool Live, bool ChunkStart)[] NativeModel(byte[] bytes) {
        var reader = new Reader(bytes);
        bool slim = reader.Read(1) == 0;
        uint flags = slim ? reader.Read(1) * 64 : reader.Read(10);
        uint length = reader.Var(8);

        if ((flags & 4) != 0) {
            reader.Var(5);
            reader.Var(3);
        } else if ((flags & 0x32) != 0) {
            reader.Var(5);
        }

        if ((flags & 2) != 0)
            reader.Var(6);

        if ((flags & 4) != 0)
            reader.Var(6);

        if ((flags & 8) != 0)
            reader.Var(6);

        if ((flags & 0x30) != 0)
            reader.Var(6);

        if ((flags & 64) != 0 && !slim)
            reader.Var(3);

        if ((flags & 0x100) != 0)
            reader.Var(4);

        if ((flags & 0x200) != 0)
            reader.Var(6);

        if (!slim)
            reader.Var(3);

        int safePoints = (int)reader.Var(2);
        int rangeCount = slim ? 0 : (int)reader.Var(1);
        int offsetWidth = length == 1 ? 0 : BitOperations.Log2(length - 1) + 1;

        for (int index = 0; index < safePoints; ++index)
            reader.Read(offsetWidth);

        var ranges = new List<(uint Start, uint End)>();
        uint previousEnd = 0;
        uint total = 0;

        for (int index = 0; index < rangeCount; ++index) {
            uint start = previousEnd + reader.Var(6);
            uint end = start + reader.Var(6) + 1;
            ranges.Add((start, end));
            previousEnd = end;
            total += end - start;
        }

        int registers = reader.Read(1) == 0 ? 0 : (int)reader.Var(2);
        int tracked = 0;
        int untracked = 0;

        if (reader.Read(1) != 0) {
            tracked = (int)reader.Var(2);
            untracked = (int)reader.Var(1);
        }

        uint slotFlags = 1;

        for (int index = 0; index < registers; ++index) {
            if (slotFlags != 0) {
                reader.Var(3);
                slotFlags = reader.Read(2);
            } else {
                reader.Var(2);
            }
        }

        foreach (int count in new[] { tracked, untracked }) {
            slotFlags = 1;

            for (int index = 0; index < count; ++index) {
                reader.Read(2);

                if (slotFlags != 0) {
                    reader.Var(6);
                    slotFlags = reader.Read(2);
                } else {
                    reader.Var(4);
                }
            }
        }

        int slots = registers + tracked;

        if (safePoints != 0 || slots == 0 || rangeCount == 0)
            return [];

        int chunks = (int)((total + 63) / 64);
        int pointerWidth = (int)reader.Var(3);

        if (pointerWidth == 0)
            return [];

        int table = reader.Position;
        int states = (table + chunks * pointerWidth + 7) & ~7;
        var previousState = new bool[slots];
        var output = new List<(uint, int, bool, bool)>();

        for (int chunk = 0; chunk < chunks; ++chunk) {
            reader.Position = table + chunk * pointerWidth;
            uint pointer = reader.Read(pointerWidth);

            if (pointer == 0)
                continue;

            reader.Position = states + (int)pointer - 1;
            var indexes = LiveSlots(reader, slots);
            int finalPosition = reader.Position;
            reader.Position += indexes.Count;

            foreach (int slot in indexes) {
                var final = new Reader(bytes) { Position = finalPosition++ };
                bool atEnd = final.Read(1) != 0;
                var offsets = new List<uint>();

                while (reader.Read(1) != 0)
                    offsets.Add(reader.Read(6));

                bool atStart = atEnd ^ ((offsets.Count & 1) != 0);

                if (previousState[slot] != atStart)
                    output.Add((Physical((uint)chunk * 64), slot, atStart, true));

                bool state = atStart;

                foreach (uint offset in offsets) {
                    state = !state;
                    output.Add((Physical((uint)chunk * 64 + offset), slot, state, false));
                }

                previousState[slot] = atEnd;
            }
        }

        return output.OrderBy(value => value.Item1).ThenBy(value => value.Item2).ToArray();

        uint Physical(uint logical) {
            uint cumulative = 0;

            foreach (var range in ranges) {
                uint end = cumulative + range.End - range.Start;

                if (logical < end)
                    return range.Start + logical - cumulative;

                cumulative = end;
            }

            throw new Exception("Oracle transition is outside half-open interruptible ranges.");
        }
    }

    private static List<int> LiveSlots(Reader reader, int slots) {
        var result = new List<int>();

        if (reader.Read(1) == 0) {
            for (int index = 0; index < slots; ++index)
                if (reader.Read(1) != 0)
                    result.Add(index);

            return result;
        }

        bool skip = reader.Read(1) == 0;
        int first = (int)reader.Var(skip ? 4 : 2);
        skip = !skip;
        bool report = true;

        while (first < slots) {
            int count = (int)reader.Var(skip ? 4 : 2) + 1;

            if (report)
                for (int index = first; index < first + count; ++index)
                    result.Add(index);

            first += count;
            skip = !skip;
            report = !report;
        }

        return result;
    }

    private sealed class Reader(byte[] bytes) {
        internal int Position;

        internal uint Read(int count) {
            uint value = 0;

            for (int index = 0; index < count; ++index, ++Position)
                value |= (uint)((bytes[Position / 8] >> (Position % 8)) & 1) << index;

            return value;
        }

        internal uint Var(int width) {
            uint result = 0;

            for (int shift = 0; ; shift += width) {
                uint part = Read(width + 1);
                result |= (part & ((1U << width) - 1)) << shift;

                if ((part & (1U << width)) == 0)
                    return result;
            }
        }
    }

    private static void Assert(bool condition, string message) {
        if (!condition)
            throw new Exception(message);
    }
}
