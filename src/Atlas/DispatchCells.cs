using System.Buffers.Binary;
using System.Runtime.InteropServices;

namespace Atlas;

public enum DispatchCellStatus : byte { Valid, Unaligned, MissingStorage, UnknownStub, UnknownInterface, UnsupportedEncoding, MissingTerminator, WrongRegister, ContractMismatch }

public readonly record struct InterfaceDispatchCell(ulong Address, ulong Stub, ulong EncodedInterface,
    ulong Terminator, int InterfaceType, ushort Slot, IndexRange Uses, bool Hydrated, byte Register,
    IndexRange DictionarySlots = default);

public readonly record struct RejectedDispatchCell(ulong Address, DispatchCellStatus Status);

public sealed class DispatchCells {
    public readonly List<InterfaceDispatchCell> Cells = new();
    public readonly List<DispatchCellUse> Uses = new();
    public readonly List<RejectedDispatchCell> Rejected = new();
    public readonly List<int> DictionarySlots = new();

    public DispatchCells(Extraction extraction, CodeFlow code) {
        var candidates = code.DispatchCellUses.ToArray();
        Array.Sort(candidates, static (left, right) => {
            int order = left.Cell.CompareTo(right.Cell);
            return order != 0 ? order : left.Instruction.CompareTo(right.Instruction);
        });
        Cells.EnsureCapacity(candidates.Length);
        Uses.EnsureCapacity(candidates.Length);
        var stubs = new Dictionary<ulong, byte>();

        for (int first = 0; first < candidates.Length;) {
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
        var cellIndex = new Dictionary<ulong, int>(Cells.Count + extraction.Dictionaries.InterfaceCells.Count);
        for (int i = 0; i < Cells.Count; ++i)
            cellIndex.Add(Cells[i].Address, i);
        var sources = new List<(int Cell, int Slot)>(extraction.Dictionaries.InterfaceCells.Count);
        for (int i = 0; i < extraction.Dictionaries.Slots.Count; ++i) {
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
            int end = first + 1;
            while (end < sources.Count && sources[end].Cell == sources[first].Cell)
                ++end;
            int index = sources[first].Cell;
            Cells[index] = Cells[index] with { DictionarySlots = new IndexRange(DictionarySlots.Count, end - first) };
            for (int i = first; i < end; ++i)
                DictionarySlots.Add(sources[i].Slot);
            first = end;
        }
        Cells.Sort(static (left, right) => left.Address.CompareTo(right.Address));
    }

    internal static DispatchCellStatus Read(Extraction extraction, Dictionary<ulong, byte> stubs, ulong address,
        out InterfaceDispatchCell cell, ulong expectedInterface = 0, uint expectedSlot = 0) {
        cell = default;
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
                if (section.Executable && offset <= (ulong)section.FileSize && (ulong)section.FileSize - offset >= 8) {
                    var instructions = extraction.Image.FileData.AsSpan(section.FileOffset + (int)offset, 8);
                    // Windows x64s initial stub faults on a null receiver, then jumps to slow dispatch
                    // The cell contract and run below must independently agree before this code shape is useful
                    if (instructions[0] == 0x80 && instructions[1] == 0x39 && instructions[2] == 0
                        && instructions[3] is 0xE9 or 0xEB) {
                        long target = instructions[3] == 0xEB ? (long)stub + 5 + unchecked((sbyte)instructions[4])
                            : (long)stub + 8 + BinaryPrimitives.ReadInt32LittleEndian(instructions[4..]);
                        if (target >= 0 && extraction.Image.IsExecutable((ulong)target)) {
                            int slowSectionIndex = extraction.Image.FindSection((ulong)target);
                            ref readonly var slowSection = ref extraction.Image.Sections[slowSectionIndex];
                            ulong slowOffset = (ulong)target - extraction.Image.ImageBase - slowSection.Rva;
                            if (slowOffset <= (ulong)slowSection.FileSize && (ulong)slowSection.FileSize - slowOffset >= 15) {
                                var slow = extraction.Image.FileData.AsSpan(slowSection.FileOffset + (int)slowOffset, 15);
                                int skip = slow[0] == 0x4D && ((slow[1] == 0x8B && slow[2] == 0xDA)
                                    || (slow[1] == 0x89 && slow[2] == 0xD3)) ? 3 : 0;
                                if (slow[skip] == 0x4C && slow[skip + 1] == 0x8D && slow[skip + 2] == 0x15 && slow[skip + 7] == 0xE9) {
                                    long resolve = target + skip + 7 + BinaryPrimitives.ReadInt32LittleEndian(slow[(skip + 3)..]);
                                    long transition = target + skip + 12 + BinaryPrimitives.ReadInt32LittleEndian(slow[(skip + 8)..]);
                                    if (resolve >= 0 && transition >= 0 && extraction.Image.IsExecutable((ulong)resolve)
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
                cell = new InterfaceDispatchCell(address, stub, encoded, address + (uint)distance * 16,
                    interfaceType, (ushort)nextData, default, region.Hydrated, cellRegister);
                return DispatchCellStatus.Valid;
            }
            if (nextStub != stub)
                break;
            status = Interface(extraction, address + (uint)distance * 16 + 8, nextData, out _, expectedInterface != 0);
            if (status != DispatchCellStatus.Valid)
                return status;
        }
        return DispatchCellStatus.MissingTerminator;
    }

    private static DispatchCellStatus Interface(Extraction extraction, ulong address, ulong encoded, out int type,
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
            return extraction.Types.Types[type].ElementType == 0x15 ? DispatchCellStatus.Valid : DispatchCellStatus.UnknownInterface;
        if (!allowUnbound || (target & 7) != 0)
            return DispatchCellStatus.UnknownInterface;

        // A typed dictionary recipe identifies its own cell independently
        // An intervening interface need not have a retained reflection identity
        int targetRegionIndex = extraction.Memory.Find(target);
        if (targetRegionIndex < 0)
            return DispatchCellStatus.MissingStorage;
        ref readonly var targetRegion = ref extraction.Memory.Regions[targetRegionIndex];
        ulong targetOffset = target - targetRegion.Start;
        if ((targetRegion.Writable && !targetRegion.Hydrated) || (ulong)targetRegion.Data.Length - targetOffset < 24)
            return DispatchCellStatus.UnknownInterface;
        uint flags = BinaryPrimitives.ReadUInt32LittleEndian(targetRegion.Data.Span[(int)targetOffset..]);
        return (flags >> 26 & 31) == 0x15 ? DispatchCellStatus.Valid : DispatchCellStatus.UnknownInterface;
    }
}
