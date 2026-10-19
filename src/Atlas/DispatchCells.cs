using System.Buffers.Binary;
using System.Runtime.InteropServices;

namespace Atlas;

public enum DispatchCellStatus : byte {
    Valid,
    Unaligned,
    MissingStorage,
    UnknownStub,
    UnknownInterface,
    UnsupportedEncoding,
    MissingTerminator,
    WrongRegister,
    ContractMismatch
}

public enum DispatchCellStorage : byte { File, Rehydrated, ZeroInitialized, FileAndZeroInitialized }

public readonly record struct InterfaceDispatchCell {
    public ulong Address { get; init; }
    public ulong Stub { get; init; }
    public ulong EncodedInterface { get; init; }
    public ulong Terminator { get; init; }
    internal int InterfaceType { get; init; }
    public ushort Slot { get; init; }
    public IndexRange Uses { get; init; }
    public DispatchCellStorage Storage { get; init; }
    public bool Hydrated => Storage == DispatchCellStorage.Rehydrated;
    public byte Register { get; init; }
    public IndexRange DictionarySlots { get; init; }
    public int Metadata { get; init; }
    public ulong CachedMethodTable { get; init; }
    public ulong CachedCode { get; init; }

    internal InterfaceDispatchCell(
        ulong address,
        ulong stub,
        ulong encodedInterface,
        ulong terminator,
        int interfaceType,
        ushort slot,
        IndexRange uses,
        bool hydrated,
        byte register,
        IndexRange dictionarySlots = default,
        int metadata = 0) {
        Address = address;
        Stub = stub;
        EncodedInterface = encodedInterface;
        Terminator = terminator;
        InterfaceType = interfaceType;
        Slot = slot;
        Uses = uses;
        Storage = hydrated ? DispatchCellStorage.Rehydrated : DispatchCellStorage.File;
        Register = register;
        DictionarySlots = dictionarySlots;
        Metadata = metadata;
    }
}

public readonly record struct RejectedDispatchCell(ulong Address, DispatchCellStatus Status);

public readonly record struct GvmDispatchCell(
    ulong Address, int Metadata, IndexRange Uses, IndexRange DictionarySlots,
    ulong CachedMethodTable, ulong CachedCode, DispatchCellStorage Storage);

public sealed class DispatchCells {
    private readonly Extraction extraction;
    internal readonly List<InterfaceDispatchCell> Cells = new();
    internal readonly List<DispatchCellUse> Uses = new();
    internal readonly List<RejectedDispatchCell> Rejected = new();
    internal readonly List<int> DictionarySlots = new();
    internal readonly List<GvmDispatchCell> GvmCells = new();
    private readonly DispatchCellUse[] unprovenUses;

    public ReadOnlySpan<InterfaceDispatchCell> CellEntries => CollectionsMarshal.AsSpan(Cells);
    public ReadOnlySpan<DispatchCellUse> UseEntries => CollectionsMarshal.AsSpan(Uses);
    public ReadOnlySpan<RejectedDispatchCell> RejectedEntries => CollectionsMarshal.AsSpan(Rejected);
    public ReadOnlySpan<int> DictionarySlotPositions => CollectionsMarshal.AsSpan(DictionarySlots);
    public ReadOnlySpan<GvmDispatchCell> GvmCellEntries => CollectionsMarshal.AsSpan(GvmCells);
    public ReadOnlySpan<DispatchCellUse> UnprovenUseEntries => unprovenUses;
    public RuntimeTypeReference InterfaceTypeAt(int position) => extraction.RuntimeTypeAt(Cells[position].InterfaceType);

    public DispatchCells(Extraction extraction, CodeFlow code, CancellationToken cancellationToken = default) {
        cancellationToken.ThrowIfCancellationRequested();

        this.extraction = extraction;
        unprovenUses = code.UnprovenDispatchCellUseEntries.ToArray();
        var candidates = code.DispatchCellUses.ToArray();
        Array.Sort(candidates, static (left, right) => {
            int order = left.Cell.CompareTo(right.Cell);
            return order != 0 ? order : left.Instruction.CompareTo(right.Instruction);
        });

        Cells.EnsureCapacity(candidates.Length);
        Uses.EnsureCapacity(candidates.Length);

        var stubs = new Dictionary<ulong, byte>();

        if (extraction.DispatchCellMetadata.Layout == DispatchCellLayout.CachedMethodTableAndCode) {
            ReadIndexed(extraction, candidates, cancellationToken);
            AttachIndexedDictionarySlots(cancellationToken);
            foreach (var use in unprovenUses) {
                if (use.Cell != 0)
                    Rejected.Add(new(use.Cell, DispatchCellStatus.UnknownStub));
            }
            return;
        }

        for (int first = 0; first < candidates.Length;) {
            cancellationToken.ThrowIfCancellationRequested();

            int end = first + 1;

            while (end < candidates.Length && candidates[end].Cell == candidates[first].Cell)
                ++end;

            ulong address = candidates[first].Cell;
            var status = Read(extraction, stubs, address, out var cell);

            if (status == DispatchCellStatus.Valid) {
                int start = Uses.Count;

                for (int i = first; i < end; ++i) {
                    if (candidates[i].Register == cell.Register)
                        Uses.Add(candidates[i]);
                }

                if (Uses.Count != start)
                    Cells.Add(cell with { Uses = new IndexRange(start, Uses.Count - start) });
                else
                    Rejected.Add(new RejectedDispatchCell(address, DispatchCellStatus.WrongRegister));
            } else {
                Rejected.Add(new RejectedDispatchCell(address, status));
            }

            first = end;
        }

        if (extraction.Dictionaries.InterfaceCells.Count == 0)
            return;

        var cellIndex = new Dictionary<ulong, int>(
            Cells.Count + extraction.Dictionaries.InterfaceCells.Count);

        for (int i = 0; i < Cells.Count; ++i)
            cellIndex.Add(Cells[i].Address, i);

        var sources = new List<(int Cell, int Slot)>(extraction.Dictionaries.InterfaceCells.Count);

        for (int i = 0; i < extraction.Dictionaries.Slots.Count; ++i) {
            cancellationToken.ThrowIfCancellationRequested();

            var slot = extraction.Dictionaries.Slots[i];
            if (slot.Cell == 0)
                continue;

            var cell = extraction.Dictionaries.InterfaceCells[slot.Cell - 1];
            if (!cellIndex.TryGetValue(cell.Address, out int index)) {
                index = Cells.Count;
                cellIndex.Add(cell.Address, index);
                Cells.Add(cell);
            }

            sources.Add((index, i));
        }

        sources.Sort(static (left, right) => {
            int order = left.Cell.CompareTo(right.Cell);
            return order != 0 ? order : left.Slot.CompareTo(right.Slot);
        });

        DictionarySlots.EnsureCapacity(sources.Count);

        for (int first = 0; first < sources.Count;) {
            cancellationToken.ThrowIfCancellationRequested();

            int end = first + 1;

            while (end < sources.Count && sources[end].Cell == sources[first].Cell)
                ++end;

            int index = sources[first].Cell;
            Cells[index] = Cells[index] with {
                DictionarySlots = new IndexRange(DictionarySlots.Count, end - first)
            };

            for (int i = first; i < end; ++i)
                DictionarySlots.Add(sources[i].Slot);

            first = end;
        }

        Cells.Sort(static (left, right) => left.Address.CompareTo(right.Address));
    }

    internal static DispatchCellStatus Read(
        Extraction extraction,
        Dictionary<ulong, byte> stubs,
        ulong address,
        out InterfaceDispatchCell cell,
        ulong expectedInterface = 0,
        uint expectedSlot = 0) {
        cell = default;

        if (extraction.DispatchCellMetadata.Layout == DispatchCellLayout.CachedMethodTableAndCode) {
            int info = extraction.DispatchCellMetadata.Find(address);
            if (info < 0)
                return DispatchCellStatus.MissingStorage;

            ref readonly var entry = ref extraction.DispatchCellMetadata.Entries[info];
            if ((address - entry.FirstCell) % 16 != 0)
                return DispatchCellStatus.Unaligned;

            if (entry.IsGvm || (expectedInterface != 0 && (expectedInterface != entry.Type || expectedSlot != entry.Slot)))
                return DispatchCellStatus.ContractMismatch;

            if ((entry.Status & MetadataFactStatus.InvalidHandle) != 0) {
                return DispatchCellStatus.UnknownInterface;
            }

            var cache = ReadCache(extraction.Image, extraction.Memory, address);
            cell = new InterfaceDispatchCell(address, 0, 0, 0, extraction.Types.Index[entry.Type],
                entry.Slot, default, false, 11, metadata: info + 1) {
                CachedMethodTable = cache.MethodTable,
                CachedCode = cache.Code,
                Storage = cache.Storage
            };
            return DispatchCellStatus.Valid;
        }

        if ((address & 15) != 0)
            return DispatchCellStatus.Unaligned;

        int regionIndex = extraction.Memory.Find(address);
        if (regionIndex < 0)
            return DispatchCellStatus.MissingStorage;

        ref readonly var region = ref extraction.Memory.Regions[regionIndex];
        var bytes = region.Data.Span[(int)(address - region.Start)..];
        if (bytes.Length < 32)
            return DispatchCellStatus.MissingStorage;

        ulong stub = BinaryPrimitives.ReadUInt64LittleEndian(bytes);
        ref byte cellRegister = ref CollectionsMarshal.GetValueRefOrAddDefault(stubs, stub, out bool seen);

        if (!seen) {
            int sectionIndex = extraction.Image.FindSection(stub);
            if (sectionIndex >= 0) {
                ref readonly var section = ref extraction.Image.Sections[sectionIndex];
                ulong offset = stub - extraction.Image.ImageBase - section.Rva;
                if (section.Executable
                    && offset <= (ulong)section.FileSize
                    && (ulong)section.FileSize - offset >= 8) {
                    var instructions = extraction.Image.FileData.AsSpan(
                        section.FileOffset + (int)offset,
                        8);

                    // Windows x64s initial stub faults on a null receiver, then jumps to slow dispatch
                    // The cell contract and run below must independently agree before this code shape is useful
                    if (instructions[0] == 0x80
                        && instructions[1] == 0x39
                        && instructions[2] == 0
                        && instructions[3] is 0xE9 or 0xEB) {
                        long target = instructions[3] == 0xEB
                            ? (long)stub + 5 + unchecked((sbyte)instructions[4])
                            : (long)stub + 8 + BinaryPrimitives.ReadInt32LittleEndian(instructions[4..]);
                        if (target >= 0 && extraction.Image.IsExecutable((ulong)target)) {
                            int slowSectionIndex = extraction.Image.FindSection((ulong)target);
                            ref readonly var slowSection = ref extraction.Image.Sections[slowSectionIndex];
                            ulong slowOffset = (ulong)target - extraction.Image.ImageBase - slowSection.Rva;
                            if (slowOffset <= (ulong)slowSection.FileSize
                                && (ulong)slowSection.FileSize - slowOffset >= 15) {
                                var slow = extraction.Image.FileData.AsSpan(
                                    slowSection.FileOffset + (int)slowOffset,
                                    15);
                                int skip = slow[0] == 0x4D
                                    && ((slow[1] == 0x8B && slow[2] == 0xDA)
                                        || (slow[1] == 0x89 && slow[2] == 0xD3))
                                        ? 3
                                        : 0;

                                if (slow[skip] == 0x4C
                                    && slow[skip + 1] == 0x8D
                                    && slow[skip + 2] == 0x15
                                    && slow[skip + 7] == 0xE9) {
                                    long resolve = target + skip + 7
                                        + BinaryPrimitives.ReadInt32LittleEndian(slow[(skip + 3)..]);
                                    long transition = target + skip + 12
                                        + BinaryPrimitives.ReadInt32LittleEndian(slow[(skip + 8)..]);

                                    if (resolve >= 0
                                        && transition >= 0
                                        && extraction.Image.IsExecutable((ulong)resolve)
                                        && extraction.Image.IsExecutable((ulong)transition))
                                        cellRegister = skip == 0 ? (byte)11 : (byte)10;
                                }
                            }
                        }
                    }
                }
            }
        }

        if (cellRegister == 0)
            return DispatchCellStatus.UnknownStub;

        ulong encoded = BinaryPrimitives.ReadUInt64LittleEndian(bytes[8..]);
        var status = Interface(extraction, address + 8, encoded, out int interfaceType);
        if (status != DispatchCellStatus.Valid)
            return status;

        if (expectedInterface != 0 && extraction.Types.Types[interfaceType].Address != expectedInterface)
            return DispatchCellStatus.ContractMismatch;

        // InterfaceDispatchCellSectionNode emits at most 32 cells per run
        // Keep the terminator as evidence for the slot shared by that run
        for (int distance = 1; distance <= 32 && distance <= (bytes.Length - 16) / 16; ++distance) {
            ulong nextStub = BinaryPrimitives.ReadUInt64LittleEndian(bytes[(distance * 16)..]);
            ulong nextData = BinaryPrimitives.ReadUInt64LittleEndian(bytes[(distance * 16 + 8)..]);
            if (nextStub == 0) {
                if (nextData > ushort.MaxValue)
                    return DispatchCellStatus.UnsupportedEncoding;

                if (expectedInterface != 0 && nextData != expectedSlot)
                    return DispatchCellStatus.ContractMismatch;

                cell = new InterfaceDispatchCell(
                    address,
                    stub,
                    encoded,
                    address + (uint)distance * 16,
                    interfaceType,
                    (ushort)nextData,
                    default,
                    region.Hydrated,
                    cellRegister);

                return DispatchCellStatus.Valid;
            }

            if (nextStub != stub)
                break;

            status = Interface(
                extraction,
                address + (uint)distance * 16 + 8,
                nextData,
                out _,
                expectedInterface != 0);
            if (status != DispatchCellStatus.Valid)
                return status;
        }

        return DispatchCellStatus.MissingTerminator;
    }

    private void ReadIndexed(Extraction extraction, DispatchCellUse[] candidates, CancellationToken cancellationToken) {
        int use = 0;
        int split = extraction.DispatchCellMetadata.InterfaceCount;
        var entries = extraction.DispatchCellMetadata.Entries;
        // The source directory groups interface and GVM contracts separately.
        // Visit the two contiguous regions in address order to merge uses once.
        if (split != 0 && split < entries.Length && entries[0].FirstCell > entries[split].FirstCell) {
            ReadRange(split, entries.Length);
            ReadRange(0, split);
        } else {
            ReadRange(0, split);
            ReadRange(split, entries.Length);
        }

        while (use < candidates.Length)
            Reject(candidates[use++]);

        void ReadRange(int first, int end) {
            for (int info = first; info < end; ++info) {
                cancellationToken.ThrowIfCancellationRequested();
                var entry = extraction.DispatchCellMetadata.Entries[info];
                for (int offset = 0; offset < entry.CellCount; ++offset) {
                    ulong address = entry.FirstCell + (uint)offset * 16UL;
                    while (use < candidates.Length && candidates[use].Cell < address)
                        Reject(candidates[use++]);

                    if ((entry.Status & MetadataFactStatus.InvalidHandle) != 0) {
                        Rejected.Add(new(address, DispatchCellStatus.UnknownInterface));
                        while (use < candidates.Length && candidates[use].Cell == address) {
                            ++use;
                        }
                        continue;
                    }

                    int start = Uses.Count;
                    while (use < candidates.Length && candidates[use].Cell == address) {
                        if (candidates[use].Register == 11)
                            Uses.Add(candidates[use]);
                        else
                            Rejected.Add(new(address, DispatchCellStatus.WrongRegister));
                        ++use;
                    }

                    var uses = new IndexRange(start, Uses.Count - start);
                    var cache = ReadCache(extraction.Image, extraction.Memory, address);
                    if (entry.IsGvm) {
                        GvmCells.Add(new GvmDispatchCell(address, info + 1, uses, default,
                            cache.MethodTable, cache.Code, cache.Storage));
                    } else {
                        Cells.Add(new InterfaceDispatchCell(address, 0, 0, 0, extraction.Types.Index[entry.Type],
                            entry.Slot, uses, false, 11, metadata: info + 1) {
                            CachedMethodTable = cache.MethodTable,
                            CachedCode = cache.Code,
                            Storage = cache.Storage
                        });
                    }
                }
            }
        }

        void Reject(DispatchCellUse candidate) {
            int info = extraction.DispatchCellMetadata.Find(candidate.Cell);
            var status = info >= 0 ? DispatchCellStatus.Unaligned : DispatchCellStatus.MissingStorage;
            Rejected.Add(new(candidate.Cell, status));
        }
    }

    private void AttachIndexedDictionarySlots(CancellationToken cancellationToken) {
        if ((extraction.Stages & ExtractionStage.DictionaryBindings) == 0)
            return;

        var positions = new Dictionary<ulong, (int Index, bool Gvm)>(Cells.Count + GvmCells.Count);
        for (int i = 0; i < Cells.Count; ++i)
            positions.Add(Cells[i].Address, (i, false));
        for (int i = 0; i < GvmCells.Count; ++i)
            positions.Add(GvmCells[i].Address, (i, true));

        var sources = new List<(int Cell, bool Gvm, int Slot)>();
        for (int i = 0; i < extraction.Dictionaries.Slots.Count; ++i) {
            cancellationToken.ThrowIfCancellationRequested();
            var slot = extraction.Dictionaries.Slots[i];
            if ((slot.Cell != 0 || slot.GvmCellMetadata != 0) && positions.TryGetValue(slot.Value, out var position))
                sources.Add((position.Index, position.Gvm, i));
        }

        sources.Sort(static (left, right) => {
            int order = left.Gvm.CompareTo(right.Gvm);
            if (order == 0)
                order = left.Cell.CompareTo(right.Cell);
            return order != 0 ? order : left.Slot.CompareTo(right.Slot);
        });

        DictionarySlots.EnsureCapacity(sources.Count);
        for (int first = 0; first < sources.Count;) {
            int end = first + 1;
            while (end < sources.Count && sources[end].Cell == sources[first].Cell && sources[end].Gvm == sources[first].Gvm)
                ++end;

            int index = sources[first].Cell;
            var range = new IndexRange(DictionarySlots.Count, end - first);
            if (sources[first].Gvm)
                GvmCells[index] = GvmCells[index] with { DictionarySlots = range };
            else
                Cells[index] = Cells[index] with { DictionarySlots = range };
            for (int i = first; i < end; ++i)
                DictionarySlots.Add(sources[i].Slot);
            first = end;
        }
    }

    private static (ulong MethodTable, ulong Code, DispatchCellStorage Storage) ReadCache(
        PeImage image, RuntimeMemory memory, ulong address) {
        int regionIndex = memory.Find(address);
        if (regionIndex >= 0) {
            ref readonly var region = ref memory.Regions[regionIndex];
            var bytes = region.Bytes[(int)(address - region.Start)..];
            if (bytes.Length >= 16) {
                return (BinaryPrimitives.ReadUInt64LittleEndian(bytes), BinaryPrimitives.ReadUInt64LittleEndian(bytes[8..]),
                    region.Hydrated ? DispatchCellStorage.Rehydrated : DispatchCellStorage.File);
            }
        }

        int sectionIndex = image.FindSection(address);
        if (sectionIndex < 0) {
            throw new InvalidDataException($"Dispatch cell at 0x{address:X} has no mapped storage.");
        }

        ref readonly var section = ref image.Sections[sectionIndex];
        ulong offset = address - image.ImageBase - section.Rva;
        if (16 > section.VirtualSize - offset) {
            throw new InvalidDataException($"Dispatch cell at 0x{address:X} extends beyond mapped storage.");
        }

        // RuntimeMemory retains all initialized bytes, including hydration overlays.
        // Uncovered bytes inside the mapped section are the PE's zero-filled tail.
        Span<byte> cache = stackalloc byte[16];
        cache.Clear();
        ulong end = address + 16;
        int initialized = 0;
        bool hydrated = false;

        foreach (ref readonly var region in memory.RegionEntries) {
            if (region.Start >= end) {
                break;
            }

            ulong first = Math.Max(address, region.Start);
            ulong last = Math.Min(end, region.Start + (uint)region.Bytes.Length);
            if (first >= last) {
                continue;
            }

            int length = (int)(last - first);
            region.Bytes.Slice((int)(first - region.Start), length).CopyTo(cache[(int)(first - address)..]);
            initialized += length;
            hydrated |= region.Hydrated;
        }

        var storage = (hydrated, initialized) switch {
            (true, _) => DispatchCellStorage.Rehydrated,
            (_, 0) => DispatchCellStorage.ZeroInitialized,
            (_, 16) => DispatchCellStorage.File,
            _ => DispatchCellStorage.FileAndZeroInitialized
        };
        return (BinaryPrimitives.ReadUInt64LittleEndian(cache), BinaryPrimitives.ReadUInt64LittleEndian(cache[8..]), storage);
    }

    private static DispatchCellStatus Interface(
        Extraction extraction,
        ulong address,
        ulong encoded,
        out int type,
        bool allowUnbound = false) {
        type = 0;

        int tag = (int)(encoded & 3);
        ulong target;

        if (tag == 1) {
            target = encoded & ~3UL;
        } else if (tag is 2 or 3) {
            if ((encoded >> 32) != 0)
                return DispatchCellStatus.UnsupportedEncoding;

            long relative = (long)address + unchecked((int)encoded);
            if (relative < 0)
                return DispatchCellStatus.UnknownInterface;

            target = (ulong)relative & ~3UL;

            if (tag == 2) {
                int regionIndex = extraction.Memory.Find(target);
                if (regionIndex < 0)
                    return DispatchCellStatus.MissingStorage;

                ref readonly var region = ref extraction.Memory.Regions[regionIndex];
                ulong offset = target - region.Start;
                if ((ulong)region.Data.Length - offset < 8)
                    return DispatchCellStatus.MissingStorage;

                target = BinaryPrimitives.ReadUInt64LittleEndian(region.Data.Span[(int)offset..]);
            }
        } else {
            return DispatchCellStatus.UnsupportedEncoding;
        }

        if (extraction.Types.Index.TryGetValue(target, out type))
            return extraction.Types.Types[type].ElementType == 0x15
                ? DispatchCellStatus.Valid
                : DispatchCellStatus.UnknownInterface;

        if (!allowUnbound || (target & 7) != 0)
            return DispatchCellStatus.UnknownInterface;

        // A typed dictionary recipe identifies its own cell independently
        // An intervening interface need not have a retained reflection identity
        int targetRegionIndex = extraction.Memory.Find(target);
        if (targetRegionIndex < 0)
            return DispatchCellStatus.MissingStorage;

        ref readonly var targetRegion = ref extraction.Memory.Regions[targetRegionIndex];
        ulong targetOffset = target - targetRegion.Start;
        if ((targetRegion.Writable && !targetRegion.Hydrated)
            || (ulong)targetRegion.Data.Length - targetOffset < 24)
            return DispatchCellStatus.UnknownInterface;

        uint flags = BinaryPrimitives.ReadUInt32LittleEndian(targetRegion.Data.Span[(int)targetOffset..]);

        return (flags >> 26 & 31) == 0x15
            ? DispatchCellStatus.Valid
            : DispatchCellStatus.UnknownInterface;
    }
}
