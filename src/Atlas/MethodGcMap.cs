namespace Atlas;

public readonly record struct MethodGcEntry(
    uint Begin,
    uint End,
    uint Address,
    MethodGcInfo? Info,
    string? Error);

public sealed class MethodGcMap {
    public readonly int Version;
    internal readonly MethodGcEntry[] Methods;
    public ReadOnlySpan<MethodGcEntry> MethodEntries => Methods;

    public MethodGcMap(
        PeImage image,
        ReadyToRun header,
        UnwindTables unwind,
        ManagedUnwind managed,
        CancellationToken cancellationToken = default) {
        cancellationToken.ThrowIfCancellationRequested();

        header = header.ValidateSource(image);

        Version = header.Format.MethodGcVersion;
        var boundaries = unwind.Infos.Select(info => info.Address).Order().ToArray();

        int count = 0;

        foreach (var frame in managed.Frames) {
            cancellationToken.ThrowIfCancellationRequested();

            if ((frame.Flags & 3) == 0)
                ++count;
        }

        var blobs = new Dictionary<uint, (MethodGcInfo? Info, string? Error)>();
        Methods = new MethodGcEntry[count];

        int index = 0;

        foreach (var frame in managed.Frames) {
            cancellationToken.ThrowIfCancellationRequested();

            if ((frame.Flags & 3) != 0)
                continue;

            uint begin = unwind.Entries[frame.Entry - 1].Function.Begin;
            uint address = checked(frame.Trailer + frame.HeaderLength);

            if (!blobs.TryGetValue(address, out var blob)) {
                try {
                    var file = image.FileRange(image.ImageBase + address);
                    int length = file.Count;

                    int next = Array.BinarySearch(boundaries, address);
                    if (next >= 0)
                        throw new InvalidDataException("GC data overlaps a Windows unwind header.");

                    next = ~next;
                    if (next < boundaries.Length)
                        length = (int)Math.Min((uint)length, boundaries[next] - address);

                    blob = (MethodGcInfo.Read(image.FileData.AsSpan(file.Start, length), Version, cancellationToken), null);
                } catch (Exception error) when (error is InvalidDataException or NotSupportedException) {
                    blob = (null, error.Message);
                }

                blobs.Add(address, blob);
            }

            if (blob.Info is { } info && info.CodeLength > frame.MethodEnd - begin)
                Methods[index++] = new(
                    begin, frame.MethodEnd, address, null,
                    "GC code length exceeds the managed method range.");
            else
                Methods[index++] = new(begin, frame.MethodEnd, address, blob.Info, blob.Error);
        }

        cancellationToken.ThrowIfCancellationRequested();
        System.Diagnostics.Debug.Assert(index == Methods.Length);
    }
}
