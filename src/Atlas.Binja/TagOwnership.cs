using System.Buffers;
using System.Buffers.Binary;
using System.Runtime.InteropServices;

namespace Atlas.Binja;

internal sealed unsafe class TagOwnership {
    private enum State : byte { Unvisited, Seen, Removed }

    private struct Identity {
        internal int Start, Length, Next;
        internal State State;
    }

    private readonly nint view;
    private readonly ArrayBufferWriter<byte> bytes = new();
    private readonly List<Identity> identities = new();
    private readonly Dictionary<ulong, int> buckets = new();

    internal TagOwnership(nint view) {
        this.view = view;
        fixed (byte* key = "aot-atlas:owned-tags\0"u8) {
            nint record = Core.BNBinaryViewQueryMetadata(view, key);
            if (record == 0) {
                nint existingHeader;
                fixed (byte* id = "aot-atlas:methodtable-header:v1\0"u8)
                    existingHeader = Core.BNGetAnalysisTypeById(view, id);
                if (existingHeader != 0) {
                    Core.BNFreeType(existingHeader);
                    throw new InvalidDataException("The Atlas tag ownership record is missing. Reopen the original binary in a fresh view.");
                }
                return;
            }

            try {
                if (Core.BNMetadataIsRaw(record) == 0)
                    throw new InvalidDataException("The stored Atlas tag ownership record is not raw metadata.");

                nuint length = 0;
                byte* data = Core.BNMetadataGetRaw(record, &length);
                try {
                    var input = new ReadOnlySpan<byte>(data, checked((int)length));
                    if (input.Length < 12 || !input[..8].SequenceEqual("ATTAGS01"u8))
                        throw new InvalidDataException("The stored Atlas tag ownership header is invalid.");
                    int count = BinaryPrimitives.ReadInt32LittleEndian(input[8..]);
                    input = input[12..];
                    if (count < 0 || count > input.Length / 5)
                        throw new InvalidDataException("The stored Atlas tag count exceeds its record.");

                    identities.EnsureCapacity(count);
                    buckets.EnsureCapacity(count);
                    bytes.GetSpan(input.Length);
                    for (int i = 0; i < count; ++i) {
                        if (input.Length < 4)
                            throw new InvalidDataException("An Atlas tag identity is truncated.");
                        int size = BinaryPrimitives.ReadInt32LittleEndian(input);
                        input = input[4..];
                        if (size <= 0 || size > input.Length || input[..size].Contains((byte)0) || Find(input[..size]) != 0)
                            throw new InvalidDataException("An Atlas tag identity is invalid or repeated.");
                        Add(input[..size], State.Unvisited);
                        input = input[size..];
                    }
                    if (!input.IsEmpty)
                        throw new InvalidDataException("The Atlas tag ownership record has trailing bytes.");
                } finally {
                    Core.BNFreeMetadataRaw(data);
                }
            } finally {
                Core.BNFreeMetadata(record);
            }
        }
    }

    internal void Reserve(int count) {
        identities.EnsureCapacity(checked(identities.Count + count));
        buckets.EnsureCapacity(checked(identities.Count + count));
        bytes.GetSpan(checked(count * 64));
    }

    private int Find(ReadOnlySpan<byte> id) {
        ulong hash = 14695981039346656037;
        foreach (byte value in id)
            hash = unchecked((hash ^ value) * 1099511628211);
        buckets.TryGetValue(hash, out int index);
        var records = CollectionsMarshal.AsSpan(identities);
        while (index != 0) {
            ref readonly var record = ref records[index - 1];
            if (bytes.WrittenSpan.Slice(record.Start, record.Length).SequenceEqual(id))
                return index;
            index = record.Next;
        }
        return 0;
    }

    private void Add(ReadOnlySpan<byte> id, State state) {
        ulong hash = 14695981039346656037;
        foreach (byte value in id)
            hash = unchecked((hash ^ value) * 1099511628211);
        buckets.TryGetValue(hash, out int previous);
        identities.Add(new Identity { Start = bytes.WrittenCount, Length = id.Length, Next = previous, State = state });
        bytes.Write(id);
        buckets[hash] = identities.Count;
    }

    internal bool Contains(nint tag) {
        byte* id = Core.BNTagGetId(tag);
        int index = Find(MemoryMarshal.CreateReadOnlySpanFromNullTerminated(id));
        Core.BNFreeString(id);
        if (index == 0)
            return false;
        CollectionsMarshal.AsSpan(identities)[index - 1].State = State.Seen;
        return true;
    }

    internal void Register(nint tag) {
        // The core assigns the opaque identity during registration
        Core.BNAddTag(view, tag, 1);
        byte* id = Core.BNTagGetId(tag);
        Add(MemoryMarshal.CreateReadOnlySpanFromNullTerminated(id), State.Seen);
        Core.BNFreeString(id);
    }

    internal void Remove(nint tag) {
        byte* id = Core.BNTagGetId(tag);
        int index = Find(MemoryMarshal.CreateReadOnlySpanFromNullTerminated(id));
        Core.BNFreeString(id);
        CollectionsMarshal.AsSpan(identities)[index - 1].State = State.Removed;
    }

    internal void Save(bool complete) {
        byte[] data = new byte[checked(12 + bytes.WrittenCount + identities.Count * 4)];
        "ATTAGS01"u8.CopyTo(data);
        int count = 0, length = 12;
        foreach (ref readonly var record in CollectionsMarshal.AsSpan(identities)) {
            if (record.State == State.Removed || (complete && record.State == State.Unvisited))
                continue;
            BinaryPrimitives.WriteInt32LittleEndian(data.AsSpan(length), record.Length);
            length += 4;
            bytes.WrittenSpan.Slice(record.Start, record.Length).CopyTo(data.AsSpan(length));
            length += record.Length;
            ++count;
        }

        // Ownership follows opaque core IDs, so a user tag with identical text stays independent of the generated annotation
        BinaryPrimitives.WriteInt32LittleEndian(data.AsSpan(8), count);
        fixed (byte* key = "aot-atlas:owned-tags\0"u8)
        fixed (byte* pointer = data) {
            nint record = Core.BNCreateMetadataRawData(pointer, (nuint)length);
            Core.BNBinaryViewStoreMetadata(view, key, record, 3);
            Core.BNFreeMetadata(record);
        }
    }
}
