using System.Buffers.Binary;
using System.Runtime.InteropServices;

namespace Atlas;

public enum ManagedRegionSource : byte { Unknown, Pogo, Section }
public enum ExceptionClauseKind : byte { Typed, Fault, Filter, Marker }

public struct ManagedFrame {
    public int Entry, Root, ExceptionInfo, FrameCount;
    public uint Trailer, AssociatedData, UnboxingTarget, MethodEnd;
    public byte Flags, HeaderLength, AssociatedFlags;
}

public struct ExceptionBlob {
    public uint Address, Length;
    public IndexRange Clauses;
}

public struct ExceptionClause {
    public uint Address, TryStart, TryEnd, HandlerOffset, FilterOffset, Type;
    public uint HandlerCell, FilterCell, TypeCell;
    public ExceptionClauseKind Kind;
}

public sealed class ManagedUnwind {
    public readonly ManagedRegionSource RegionSource;
    public readonly uint RegionStart, RegionLength;
    public readonly int RegionRecord;
    public readonly int AssociatedFrameCount;
    public readonly ManagedFrame[] Frames = [];
    public readonly ExceptionBlob[] Exceptions = [];
    public readonly ExceptionClause[] Clauses = [];

    public ManagedUnwind(PeImage image, UnwindTables unwind, PeDebug contributions) {
        foreach (ref readonly var contribution in CollectionsMarshal.AsSpan(contributions.Entries)) {
            if (!image.FileData.AsSpan(contribution.Name.Start, contribution.Name.Count).SequenceEqual(".managedcode$I"u8))
                continue;
            if (RegionSource != ManagedRegionSource.Unknown)
                throw new InvalidDataException("Multiple managed code contributions.");

            RegionSource = ManagedRegionSource.Pogo;
            RegionStart = contribution.Rva;
            RegionLength = contribution.Length;
            RegionRecord = contribution.FileOffset;
        }

        // Older images can retain a dedicated section even when the linker contribution record is stripped
        // Keep that evidence in the result
        if (RegionSource == ManagedRegionSource.Unknown) {
            for (int i = 0; i < image.Sections.Length; ++i) {
                ref readonly var section = ref image.Sections[i];
                if (section.Name != ".managed")
                    continue;
                if (RegionSource != ManagedRegionSource.Unknown)
                    throw new InvalidDataException("Multiple managed code sections.");

                RegionSource = ManagedRegionSource.Section;
                RegionStart = section.Rva;
                RegionLength = section.VirtualSize;
                RegionRecord = i;
            }
        }
        if (RegionSource == ManagedRegionSource.Unknown)
            return;
        if (RegionLength == 0 || !image.IsExecutable(image.ImageBase + RegionStart)
            || !image.IsMapped(image.ImageBase + RegionStart, RegionLength))
            throw new InvalidDataException("Managed code range is outside executable storage.");

        uint regionEnd = checked(RegionStart + RegionLength);
        var entries = CollectionsMarshal.AsSpan(unwind.Entries)[..unwind.DirectoryCount];
        int first = 0, last;
        while (first < entries.Length && entries[first].Function.Begin < RegionStart)
            ++first;
        for (last = first; last < entries.Length && entries[last].Function.Begin < regionEnd; ++last) { }
        Frames = new ManagedFrame[last - first];
        uint[] ehAddresses = new uint[Frames.Length];
        int root = 0, ehCount = 0;
        for (int i = 0; i < Frames.Length; ++i) {
            var entry = entries[first + i];
            if (entry.Function.End > regionEnd || entry.Indirect || entry.Parent != 0)
                throw new InvalidDataException("Managed code contains an unsupported chained or out-of-range runtime function.");

            var info = unwind.Infos[entry.Info - 1];
            ref var frame = ref Frames[i];
            frame.Entry = first + i + 1;
            frame.Trailer = checked(info.Address + info.Length);
            var bytes = image.FileRange(image.ImageBase + frame.Trailer);
            var reader = new NativeReader(image.FileData.AsSpan(bytes.Start, bytes.Count));
            frame.Flags = reader.Take(1)[0];
            int kind = frame.Flags & 3;
            if ((frame.Flags & ~31) != 0 || kind == 3)
                throw new InvalidDataException($"Invalid NativeAOT unwind flags at RVA 0x{frame.Trailer:X}.");
            if (kind == 0)
                root = i + 1;
            else if (root == 0 || (frame.Flags & 20) != 0)
                throw new InvalidDataException("NativeAOT funclet has no root or carries root-only metadata.");
            frame.Root = root;
            Frames[root - 1].MethodEnd = entry.Function.End;
            ++Frames[root - 1].FrameCount;

            if ((frame.Flags & 16) != 0) {
                ++AssociatedFrameCount;
                frame.AssociatedData = BinaryPrimitives.ReadUInt32LittleEndian(reader.Take(4));
                frame.AssociatedFlags = image.FileSpan(image.ImageBase + frame.AssociatedData, 1)[0];
                if ((frame.AssociatedFlags & ~1) != 0)
                    throw new NotSupportedException("Unsupported NativeAOT associated-data flags.");
                if ((frame.AssociatedFlags & 1) != 0) {
                    ulong cell = image.ImageBase + frame.AssociatedData + 1;
                    long target = checked((long)cell + BinaryPrimitives.ReadInt32LittleEndian(image.FileSpan(cell, 4)));
                    if (target < 0 || !image.IsExecutable((ulong)target))
                        throw new InvalidDataException("Unboxing target is outside executable storage.");
                    frame.UnboxingTarget = checked((uint)((ulong)target - image.ImageBase));
                }
            }
            if ((frame.Flags & 4) != 0) {
                int rva = BinaryPrimitives.ReadInt32LittleEndian(reader.Take(4));
                if (rva <= 0)
                    throw new InvalidDataException("NativeAOT EH pointer is outside the image.");
                ehAddresses[i] = (uint)rva;
                ++ehCount;
            }
            frame.HeaderLength = (byte)reader.Position;
        }

        var indexes = new Dictionary<uint, int>(ehCount);
        var blobs = new List<ExceptionBlob>(ehCount);
        int total = 0;
        for (int i = 0; i < Frames.Length; ++i) {
            uint address = ehAddresses[i];
            if (address == 0)
                continue;
            if (!indexes.TryGetValue(address, out int index)) {
                var range = image.FileRange(image.ImageBase + address);
                var reader = new NativeReader(image.FileData.AsSpan(range.Start, range.Count));
                int count = checked((int)reader.Unsigned());
                if (count > reader.Remaining / 3)
                    throw new InvalidDataException("Exception clause count exceeds its file-backed storage.");
                var blob = new ExceptionBlob { Address = address, Length = (uint)reader.Position, Clauses = new IndexRange(total, count) };
                total = checked(total + count);
                blobs.Add(blob);
                index = blobs.Count;
                indexes.Add(address, index);
            }
            Frames[i].ExceptionInfo = index;
        }

        Exceptions = blobs.ToArray();
        Clauses = new ExceptionClause[total];
        foreach (ref var blob in Exceptions.AsSpan()) {
            var range = image.FileRange(image.ImageBase + blob.Address);
            var reader = new NativeReader(image.FileData.AsSpan(range.Start, range.Count), (int)blob.Length);
            foreach (ref var clause in Clauses.AsSpan(blob.Clauses.Start, blob.Clauses.Count)) {
                clause.Address = checked(blob.Address + (uint)reader.Position);
                clause.TryStart = reader.Unsigned();
                uint packed = reader.Unsigned();
                clause.Kind = (ExceptionClauseKind)(packed & 3);
                if (clause.Kind == ExceptionClauseKind.Marker)
                    throw new InvalidDataException("Unsupported exception clause kind 3.");
                clause.TryEnd = checked(clause.TryStart + (packed >> 2));
                clause.HandlerCell = checked(blob.Address + (uint)reader.Position);
                clause.HandlerOffset = reader.Unsigned();
                if (clause.Kind == ExceptionClauseKind.Typed) {
                    clause.TypeCell = checked(blob.Address + (uint)reader.Position);
                    clause.Type = BinaryPrimitives.ReadUInt32LittleEndian(reader.Take(4));
                    if (clause.Type == 0 || !image.IsMapped(image.ImageBase + clause.Type, 24))
                        throw new InvalidDataException("Exception catch type is outside mapped storage.");
                } else if (clause.Kind == ExceptionClauseKind.Filter) {
                    clause.FilterCell = checked(blob.Address + (uint)reader.Position);
                    clause.FilterOffset = reader.Unsigned();
                } else if (clause.TryStart == 0 && clause.TryEnd == 0 && clause.HandlerOffset == 0) {
                    clause.Kind = ExceptionClauseKind.Marker;
                }
            }
            blob.Length = (uint)reader.Position;
        }

        foreach (ref readonly var frame in Frames.AsSpan()) {
            if (frame.ExceptionInfo == 0)
                continue;
            uint begin = entries[frame.Entry - 1].Function.Begin;
            uint length = frame.MethodEnd - begin;
            var blob = Exceptions[frame.ExceptionInfo - 1];
            foreach (ref readonly var clause in Clauses.AsSpan(blob.Clauses.Start, blob.Clauses.Count)) {
                if (clause.Kind == ExceptionClauseKind.Marker)
                    continue;
                // An empty protected range still retains its handler metadata
                if (clause.TryEnd > length || clause.HandlerOffset >= length
                    || (clause.Kind == ExceptionClauseKind.Filter && clause.FilterOffset >= length))
                    throw new InvalidDataException($"Exception clause escapes its method at RVA 0x{clause.Address:X}.");

                for (int target = 0; target < (clause.Kind == ExceptionClauseKind.Filter ? 2 : 1); ++target) {
                    uint address = begin + (target == 0 ? clause.HandlerOffset : clause.FilterOffset);
                    int low = frame.Entry - 1, limit = low + frame.FrameCount, high = limit;
                    while (low < high) {
                        int mid = low + ((high - low) >> 1);
                        if (entries[mid].Function.Begin < address)
                            low = mid + 1;
                        else
                            high = mid;
                    }
                    if (low == limit || entries[low].Function.Begin != address || (Frames[low - first].Flags & 3) != target + 1)
                        throw new InvalidDataException($"Exception target at RVA 0x{address:X} is not the recorded handler or filter of its method.");
                }
            }
        }
    }
}
