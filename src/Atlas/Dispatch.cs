using System.Buffers.Binary;
using System.Runtime.InteropServices;

namespace Atlas;

public enum DispatchKind : byte {
    Standard, Default, Static, StaticDefault
}

public enum DispatchStatus : byte {
    UnknownInterface, UnknownContext, NullImplementation, NonExecutable, Reabstraction, Diamond
}

public struct DispatchEntry {
    public ushort InterfaceIndex, InterfaceSlot, ImplementationSlot, ContextSource;
    public DispatchKind Kind;
}

public struct DispatchMap {
    public ulong Address;
    public IndexRange Entries;
    public ushort StandardCount, DefaultCount, StaticCount, StaticDefaultCount;
}

public struct SealedSlot {
    public ulong Address, EncodedTarget, Target;
    public byte Flags;
}

public struct DispatchTarget {
    public int OwnerType, InterfaceType, Entry, SealedSlot;
    public ulong Target, GenericContext;
    public bool RequiresInstantiatingThunk;
}

public readonly struct UnresolvedDispatch(int ownerType, int entry, DispatchStatus status) {
    public readonly int OwnerType = ownerType, Entry = entry;
    public readonly DispatchStatus Status = status;
}

public sealed class Dispatch {
    public readonly List<DispatchMap> Maps = new(8192);
    public readonly List<DispatchEntry> Entries = new(65536);
    public readonly List<SealedSlot> SealedSlots = new(65536);
    public readonly List<DispatchTarget> Targets = new(262144);
    public readonly List<UnresolvedDispatch> Unresolved = new(8192);
    public readonly int[] TypeMaps;
    private readonly Dictionary<ulong, int> sealedIndex = new(65536);

    public Dispatch(PeImage image, RuntimeMemory memory, MethodTables tables) {
        TypeMaps = new int[tables.Types.Count];
        var mapIndex = new Dictionary<ulong, int>(8192);
        var types = CollectionsMarshal.AsSpan(tables.Types);
        var pointers = CollectionsMarshal.AsSpan(tables.Pointers);

        for (int owner = 0; owner < types.Length; ++owner) {
            ref readonly var type = ref types[owner];
            if (type.DispatchMap == 0)
                continue;

            ref int mapId = ref CollectionsMarshal.GetValueRefOrAddDefault(mapIndex, type.DispatchMap, out bool present);
            if (!present) {
                int regionIndex = memory.Find(type.DispatchMap);
                if (regionIndex < 0)
                    throw new InvalidDataException("Dispatch map has no initialized storage.");

                ref readonly var region = ref memory.Regions[regionIndex];
                var bytes = region.Data.Span[checked((int)(type.DispatchMap - region.Start))..];
                if (bytes.Length < 8)
                    throw new InvalidDataException("Truncated dispatch map header.");

                DispatchMap map = new() {
                    Address = type.DispatchMap,
                    StandardCount = BinaryPrimitives.ReadUInt16LittleEndian(bytes),
                    DefaultCount = BinaryPrimitives.ReadUInt16LittleEndian(bytes[2..]),
                    StaticCount = BinaryPrimitives.ReadUInt16LittleEndian(bytes[4..]),
                    StaticDefaultCount = BinaryPrimitives.ReadUInt16LittleEndian(bytes[6..])
                };
                int instanceCount = map.StandardCount + map.DefaultCount;
                int staticCount = map.StaticCount + map.StaticDefaultCount;
                if (8 + instanceCount * 6 + staticCount * 8 > bytes.Length)
                    throw new InvalidDataException("Dispatch map entries exceed initialized storage.");

                map.Entries = new IndexRange(Entries.Count, instanceCount + staticCount);
                Entries.EnsureCapacity(checked(Entries.Count + map.Entries.Count));
                int offset = 8;

                for (int i = 0; i < map.Entries.Count; ++i) {
                    bool isStatic = i >= instanceCount;
                    Entries.Add(new DispatchEntry {
                        InterfaceIndex = BinaryPrimitives.ReadUInt16LittleEndian(bytes[offset..]),
                        InterfaceSlot = BinaryPrimitives.ReadUInt16LittleEndian(bytes[(offset + 2)..]),
                        ImplementationSlot = BinaryPrimitives.ReadUInt16LittleEndian(bytes[(offset + 4)..]),
                        ContextSource = isStatic ? BinaryPrimitives.ReadUInt16LittleEndian(bytes[(offset + 6)..]) : (ushort)0,
                        Kind = i < map.StandardCount ? DispatchKind.Standard
                            : i < instanceCount ? DispatchKind.Default
                            : i < instanceCount + map.StaticCount ? DispatchKind.Static : DispatchKind.StaticDefault
                    });
                    offset += isStatic ? 8 : 6;
                }

                mapId = Maps.Count + 1;
                Maps.Add(map);
            }

            TypeMaps[owner] = mapId;
            var range = Maps[mapId - 1].Entries;
            var entries = CollectionsMarshal.AsSpan(Entries);

            for (int index = range.Start; index < range.End; ++index) {
                ref readonly var entry = ref entries[index];
                if (entry.InterfaceIndex >= type.Interfaces.Count)
                    throw new InvalidDataException($"Dispatch map at 0x{type.DispatchMap:X} exceeds the interface list of 0x{type.Address:X}.");

                int sealedSlot = 0;
                if (entry.ImplementationSlot >= type.Vtable.Count && entry.ImplementationSlot < 0xFFFE) {
                    if (type.SealedVtable == 0)
                        throw new InvalidDataException($"Dispatch map requires a missing sealed vtable at 0x{type.Address:X}.");

                    // A dispatch entry proves this slot exists
                    // There is no stored table length that would justify scanning past it
                    ulong address = checked(type.SealedVtable + 4UL * (uint)(entry.ImplementationSlot - type.Vtable.Count));
                    sealedSlot = ReadSealedSlot(image, memory, address);
                }

                ulong interfaceAddress = pointers[type.Interfaces.Start + entry.InterfaceIndex];
                if (interfaceAddress == 0) {
                    Unresolved.Add(new UnresolvedDispatch(owner, index, DispatchStatus.UnknownInterface));
                    continue;
                }

                if (entry.ImplementationSlot >= 0xFFFE) {
                    Unresolved.Add(new UnresolvedDispatch(owner, index,
                        entry.ImplementationSlot == 0xFFFF ? DispatchStatus.Reabstraction : DispatchStatus.Diamond));
                    continue;
                }

                DispatchTarget target = new() {
                    OwnerType = owner,
                    InterfaceType = tables.Index[interfaceAddress],
                    Entry = index
                };

                if (entry.ContextSource != 0) {
                    if (entry.ContextSource == 1) {
                        target.GenericContext = type.Address;
                    } else {
                        int contextIndex = entry.ContextSource - 2;
                        if (contextIndex >= type.Interfaces.Count)
                            throw new InvalidDataException("Static dispatch context exceeds the interface list.");

                        target.GenericContext = pointers[type.Interfaces.Start + contextIndex];
                        if (target.GenericContext == 0) {
                            Unresolved.Add(new UnresolvedDispatch(owner, index, DispatchStatus.UnknownContext));
                            continue;
                        }
                    }
                }

                if (entry.ImplementationSlot < type.Vtable.Count) {
                    target.Target = pointers[type.Vtable.Start + entry.ImplementationSlot];
                    if (target.Target == 0) {
                        Unresolved.Add(new UnresolvedDispatch(owner, index, DispatchStatus.NullImplementation));
                        continue;
                    }
                } else {
                    ref readonly var slot = ref CollectionsMarshal.AsSpan(SealedSlots)[sealedSlot - 1];
                    target.SealedSlot = sealedSlot;
                    target.Target = slot.Target;
                    target.RequiresInstantiatingThunk = slot.Flags != 0;
                    if (target.RequiresInstantiatingThunk && entry.Kind is DispatchKind.Standard or DispatchKind.Default)
                        target.GenericContext = type.Address;
                }

                if (target.Target == 0 || (target.SealedSlot == 0 && !image.IsExecutable(target.Target))) {
                    Unresolved.Add(new UnresolvedDispatch(owner, index, DispatchStatus.NonExecutable));
                    continue;
                }

                Targets.Add(target);
            }
        }
    }

    public int ReadSealedSlot(PeImage image, RuntimeMemory memory, ulong address) {
        ref int slotId = ref CollectionsMarshal.GetValueRefOrAddDefault(sealedIndex, address, out bool known);
        if (!known) {
            int delta = BinaryPrimitives.ReadInt32LittleEndian(memory.Read(address, 4));
            ulong encoded = checked((ulong)((long)address + delta));
            ulong code = encoded & ~2UL;
            slotId = SealedSlots.Count + 1;
            SealedSlots.Add(new SealedSlot {
                Address = address,
                EncodedTarget = encoded,
                Target = image.IsExecutable(code) ? code : 0,
                Flags = (byte)(encoded & 2)
            });
        }

        return slotId;
    }
}
