using System.Runtime.InteropServices;

namespace Atlas;

public readonly record struct NativeString(uint Rva, IndexRange Data, bool Wide);

public sealed class NativeStrings {
    public readonly List<NativeString> Items = new();
    public int ScannedBytes { get; private set; }

    public NativeStrings(PeImage image, ReadOnlySpan<RtrSection> metadata) {
        var excluded = new IndexRange[metadata.Length];
        foreach (ref readonly var section in image.Sections.AsSpan()) {
            if (section.Name != ".rdata" || section.FileSize == 0)
                continue;

            ulong start = image.ImageBase + section.Rva, end = start + (uint)section.FileSize;
            int count = 0;
            foreach (ref readonly var entry in metadata) {
                ulong entryEnd = checked(entry.Start + entry.Length);
                if (entry.Length == 0 || entry.Start >= end || entryEnd <= start)
                    continue;
                int first = (int)(Math.Max(start, entry.Start) - start);
                int last = (int)(Math.Min(end, entryEnd) - start);
                excluded[count++] = new IndexRange(first, last - first);
            }
            excluded.AsSpan(0, count).Sort(static (left, right) => left.Start.CompareTo(right.Start));

            int cursor = 0;
            for (int i = 0; i <= count; ++i) {
                int limit = i == count ? section.FileSize : excluded[i].Start;
                if (limit > cursor) {
                    Read(image.FileData.AsSpan(section.FileOffset + cursor, limit - cursor),
                        section.FileOffset + cursor, section.Rva + (uint)cursor);
                    ScannedBytes = checked(ScannedBytes + limit - cursor);
                }
                if (i < count)
                    cursor = Math.Max(cursor, excluded[i].End);
            }
        }
        Items.Sort(static (left, right) => left.Rva.CompareTo(right.Rva));
    }

    private void Read(ReadOnlySpan<byte> data, int fileOffset, uint rva) {
        int position = 0;
        while (position < data.Length) {
            int length = data[position..].IndexOf((byte)0);
            if (length < 0)
                break;
            if (length >= 4) {
                var text = data.Slice(position, length);
                int exceptional = text.IndexOfAnyExceptInRange((byte)0x20, (byte)0x7E);
                bool valid = true;
                if (exceptional >= 0) {
                    foreach (byte value in text[exceptional..]) {
                        if (value is not (>= 0x20 and <= 0x7E or 9 or 10 or 13)) {
                            valid = false;
                            break;
                        }
                    }
                }
                if (valid)
                    Items.Add(new NativeString(rva + (uint)position, new IndexRange(fileOffset + position, length), false));
            }
            position += length + 1;
        }

        // Preserve overlapping byte interpretations; choosing a display type belongs to the consumer that knows which ranges are already typed
        int first = (int)(rva & 1);
        for (position = first; position + 1 < data.Length; position += 2) {
            byte low = data[position], high = data[position + 1];
            if (high == 0 && low is >= 0x20 and <= 0x7E or 9 or 10 or 13)
                continue;
            if (low == 0 && high == 0 && position - first >= 8)
                Items.Add(new NativeString(rva + (uint)first, new IndexRange(fileOffset + first, position - first), true));
            first = position + 2;
        }
    }

    public List<CodeEdge> FindReferences(ulong imageBase, ReadOnlySpan<CodeEdge> addresses) {
        var targets = new HashSet<ulong>(Items.Count);
        foreach (ref readonly var item in CollectionsMarshal.AsSpan(Items))
            targets.Add(imageBase + item.Rva);
        var references = new List<CodeEdge>();
        foreach (ref readonly var edge in addresses) {
            if (targets.Contains(edge.Target))
                references.Add(edge);
        }
        return references;
    }
}
