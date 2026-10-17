using System.Numerics;
using System.Runtime.InteropServices;
using System.Text;

namespace Atlas;

public readonly record struct InteropTypeMapGroup(
    int Vertex, int Length, uint Hash, uint GroupFixup, ulong GroupType, uint State,
    int TableOffset, uint HashMask, uint ThrowingStubFixup, ulong ThrowingStub, IndexRange Entries) {
    public bool IsValid => State == 1;
}

public readonly record struct InteropTypeMapEntry(
    int Vertex, int Length, uint Hash, uint SourceFixup, ulong SourceType,
    IndexRange NameBytes, string? Name, uint TargetFixup, ulong TargetType);

internal readonly record struct TypeMapThrowingStub(InteropTypeMap Map, int GroupIndex);

public sealed class InteropTypeMap {
    private static readonly UTF8Encoding Utf8 = new(false, true);

    public RtrSectionId Section { get; }
    public bool Present { get; }
    public ulong Address { get; }
    private readonly ReadOnlyMemory<byte> storage;
    public ReadOnlySpan<byte> Bytes => storage.Span;
    public uint HashMask { get; }

    private readonly List<InteropTypeMapGroup> groups = [];
    private readonly List<InteropTypeMapEntry> entries = [];
    public ReadOnlySpan<InteropTypeMapGroup> Groups => CollectionsMarshal.AsSpan(groups);
    public ReadOnlySpan<InteropTypeMapEntry> Entries => CollectionsMarshal.AsSpan(entries);

    internal InteropTypeMap(
        PeImage image, ReadyToRun header, RtrSectionId id, ReadOnlySpan<ulong> fixups,
        MethodTables types, List<TypeMapThrowingStub> throwingStubs, CancellationToken cancellationToken) {
        Section = id;
        var section = header.Find(id);
        Present = section.Id == (int)id;
        Address = section.Start;
        int offset = 0;

        try {
            storage = section.Length == 0 ? default : image.FileMemory(section.Start, checked((int)section.Length));
            var data = Bytes;
            var table = new NativeTable(data);
            HashMask = data.IsEmpty ? 0 : ((uint)table.BucketMask << 8) | 255;
            bool external = id == RtrSectionId.ExternalTypeMap;
            var evidence = external ? TypeEvidence.ExternalTypeMap : TypeEvidence.ProxyTypeMap;

            while (table.MoveNext()) {
                cancellationToken.ThrowIfCancellationRequested();
                offset = table.Vertex;
                var reader = new NativeReader(data, offset);
                uint groupFixup = reader.Unsigned();
                ulong groupType = Reference(groupFixup, fixups);
                types.Add(groupType, evidence);
                uint state = reader.Unsigned();
                int tableOffset = -1;
                uint hashMask = 0;
                uint stubFixup = 0;
                ulong stub = 0;
                int start = entries.Count;

                if (state == 0) {
                    stubFixup = reader.Unsigned();
                    stub = Reference(stubFixup, fixups);
                    if (!image.IsExecutable(stub))
                        throw new InvalidDataException("Throwing stub is outside executable storage.");

                    throwingStubs.Add(new(this, groups.Count));
                } else if (state == 1) {
                    tableOffset = reader.Position;
                    offset = tableOffset;
                    var nested = new NativeTable(data, tableOffset);
                    hashMask = ((uint)nested.BucketMask << 8) | 255;

                    while (nested.MoveNext()) {
                        cancellationToken.ThrowIfCancellationRequested();
                        offset = nested.Vertex;
                        var entry = new NativeReader(data, offset);
                        uint sourceFixup = 0;
                        ulong sourceType = 0;
                        IndexRange nameBytes = default;
                        string? name = null;

                        if (external) {
                            int length = checked((int)entry.Unsigned());
                            nameBytes = new(entry.Position, length);
                            name = Utf8.GetString(entry.Take(length));
                            if ((NameHash(name) & hashMask) != Hash(nested))
                                throw new InvalidDataException("External name hash does not match its runtime lookup bucket.");
                        } else {
                            sourceFixup = entry.Unsigned();
                            sourceType = Reference(sourceFixup, fixups);
                            types.Add(sourceType, evidence);
                        }

                        uint targetFixup = entry.Unsigned();
                        ulong targetType = Reference(targetFixup, fixups);
                        types.Add(targetType, evidence);
                        entries.Add(new(offset, entry.Position - offset, Hash(nested), sourceFixup,
                            sourceType, nameBytes, name, targetFixup, targetType));
                    }
                } else {
                    throw new InvalidDataException($"Unsupported type map state {state}.");
                }

                // A valid group's tuple ends where its inline table begins
                // Entries can be shared or placed before the table, so they cannot define a contiguous group extent
                groups.Add(new(table.Vertex, reader.Position - table.Vertex, Hash(table), groupFixup,
                    groupType, state, tableOffset, hashMask, stubFixup, stub,
                    new(start, entries.Count - start)));
            }
        } catch (Exception error) when (error is InvalidDataException or OverflowException or DecoderFallbackException) {
            string message = error is DecoderFallbackException ? "Invalid UTF-8 name." : error.Message;
            throw new InvalidDataException($"Type map section {(int)id} at offset 0x{offset:X}: {message}", error);
        }
    }

    internal void ValidateHashes(MethodTables types, CancellationToken cancellationToken) {
        foreach (ref readonly var group in Groups) {
            cancellationToken.ThrowIfCancellationRequested();
            if ((types.Types[types.Index[group.GroupType]].Hash & HashMask) != group.Hash)
                throw new InvalidDataException($"Type map section {(int)Section} at offset 0x{group.Vertex:X}: group hash does not match its runtime lookup bucket.");

            if (Section != RtrSectionId.ProxyTypeMap)
                continue;

            foreach (ref readonly var entry in Entries.Slice(group.Entries.Start, group.Entries.Count)) {
                cancellationToken.ThrowIfCancellationRequested();
                if ((types.Types[types.Index[entry.SourceType]].Hash & group.HashMask) != entry.Hash)
                    throw new InvalidDataException($"Type map section {(int)Section} at offset 0x{entry.Vertex:X}: source hash does not match its runtime lookup bucket.");
            }
        }
    }

    private static ulong Reference(uint index, ReadOnlySpan<ulong> fixups) {
        if (index >= fixups.Length || fixups[(int)index] == 0)
            throw new InvalidDataException($"CommonFixups index {index} is outside storage or null.");

        return fixups[(int)index];
    }

    private static uint Hash(NativeTable table) => ((uint)table.Bucket << 8) | table.LowHash;

    // NAOT ComputeNameHashCode hashes UTF-16 code units, including surrogate pairs
    private static uint NameHash(string name) {
        uint first = 0x6DA3B944;
        uint second = 0;
        for (int i = 0; i < name.Length; i += 2) {
            first = unchecked(first + BitOperations.RotateLeft(first, 5)) ^ name[i];
            if (i + 1 < name.Length)
                second = unchecked(second + BitOperations.RotateLeft(second, 5)) ^ name[i + 1];
        }

        return unchecked(first + BitOperations.RotateLeft(first, 8))
            ^ unchecked(second + BitOperations.RotateLeft(second, 8));
    }
}

public sealed class TypeMaps {
    public InteropTypeMap External { get; }
    public InteropTypeMap Proxy { get; }

    private readonly List<TypeMapThrowingStub> throwingStubs = [];
    internal ReadOnlySpan<TypeMapThrowingStub> ThrowingStubs => CollectionsMarshal.AsSpan(throwingStubs);

    internal TypeMaps(PeImage image, ReadyToRun header, ReadOnlySpan<ulong> fixups,
        MethodTables types, CancellationToken cancellationToken) {
        External = new(image, header, RtrSectionId.ExternalTypeMap, fixups, types, throwingStubs, cancellationToken);
        Proxy = new(image, header, RtrSectionId.ProxyTypeMap, fixups, types, throwingStubs, cancellationToken);
    }

    internal void ValidateHashes(MethodTables types, CancellationToken cancellationToken) {
        External.ValidateHashes(types, cancellationToken);
        Proxy.ValidateHashes(types, cancellationToken);
    }
}
