namespace Atlas;

public readonly struct MemoryRegion(ulong start, ReadOnlyMemory<byte> data, bool writable, bool hydrated) {
    public readonly ulong Start = start;
    public readonly ReadOnlyMemory<byte> Data = data;
    public readonly bool Writable = writable;
    public readonly bool Hydrated = hydrated;
}

public sealed class RuntimeMemory {
    public readonly MemoryRegion[] Regions;

    public RuntimeMemory(PeImage image, HydratedRegion hydration) {
        var regions = new List<MemoryRegion>(image.Sections.Length + 2);
        ulong hydratedEnd = hydration.Start + (uint)hydration.Length;

        foreach (ref readonly var section in image.Sections.AsSpan()) {
            if (section.FileSize == 0)
                continue;

            ulong start = image.ImageBase + section.Rva;
            ulong end = start + (uint)section.FileSize;
            var data = image.FileData.AsMemory(section.FileOffset, section.FileSize);

            if (hydration.Length != 0 && start < hydratedEnd && end > hydration.Start) {
                if (start < hydration.Start)
                    regions.Add(new MemoryRegion(start, data[..checked((int)(hydration.Start - start))], section.Writable, false));

                if (end > hydratedEnd)
                    regions.Add(new MemoryRegion(hydratedEnd, data[checked((int)(hydratedEnd - start))..], section.Writable, false));
            } else {
                regions.Add(new MemoryRegion(start, data, section.Writable, false));
            }
        }

        if (hydration.Length != 0)
            regions.Add(new MemoryRegion(hydration.Start, hydration.Storage.AsMemory(0, hydration.Length), true, true));

        Regions = regions.ToArray();
        Array.Sort(Regions, static (left, right) => left.Start.CompareTo(right.Start));
    }

    public int Find(ulong address) {
        int low = 0, high = Regions.Length - 1;

        while (low <= high) {
            int middle = low + ((high - low) >> 1);
            ref readonly var region = ref Regions[middle];

            if (address < region.Start)
                high = middle - 1;
            else if (address - region.Start >= (ulong)region.Data.Length)
                low = middle + 1;
            else
                return middle;
        }

        return -1;
    }

    public ReadOnlySpan<byte> Read(ulong address, int count) => ReadMemory(address, count).Span;

    public ReadOnlyMemory<byte> ReadMemory(ulong address, int count) {
        int index = Find(address);
        if (index < 0)
            throw new InvalidDataException($"No initialized bytes at 0x{address:X}.");

        ref readonly var region = ref Regions[index];
        int offset = (int)(address - region.Start);
        if (count < 0 || count > region.Data.Length - offset)
            throw new InvalidDataException($"Read at 0x{address:X} crosses an initialized memory region.");

        return region.Data.Slice(offset, count);
    }
}
