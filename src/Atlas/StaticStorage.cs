using System.Buffers.Binary;
using System.Runtime.InteropServices;

namespace Atlas;

public struct StaticConstructor {
    public int Vertex;
    public ulong Type, NonGcBase, Pointer, Descriptor, Entrypoint, GenericContext;
}

public struct GenericStatics {
    public int Vertex;
    public ulong Type, NonGcBase, GcCell, ThreadIndex;
}

public struct StaticAllocation {
    public ulong Address, RelatedType;
    public uint Flags, BaseSize;
    public IndexRange Runs;
}

public struct GcStaticCell {
    public ulong Cell, Descriptor, PreinitData;
    public byte Flags;
}

public struct ThreadStaticIndex {
    public ulong Address, TypeManager, Descriptor;
    public int Index;
    public uint InlinedOffset;
}

public enum StaticLocation : byte {
    Unknown, NonGcAddress, GcObject, ThreadObject, RuntimeBase, Ordinal
}

public struct StaticField {
    public int FieldMapIndex;
    public StaticLocation Location;
    public ulong Address, Descriptor;
    public uint Offset;
}

public sealed class StaticStorage {
    public readonly List<StaticConstructor> Constructors = new(4096);
    public readonly List<GenericStatics> Generics = new(8192);
    public readonly List<GcStaticCell> GcCells = new(8192);
    public readonly List<ulong> ThreadDescriptors = new(1024);
    public readonly List<StaticAllocation> Allocations = new(1024);
    public readonly List<GcRun> Runs = new(4096);
    public readonly Dictionary<ulong, int> AllocationIndex = new(1024);
    public readonly List<ThreadStaticIndex> ThreadIndices = new(1024);
    public readonly List<StaticField> Fields = new(4096);
    private readonly Dictionary<ulong, int> threadIndex = new(1024);

    public StaticStorage(PeImage image, ReadyToRun rtr, RuntimeMemory memory, ReadOnlySpan<ulong> common,
        ReadOnlySpan<ulong> references, ReadOnlySpan<ulong> nativeStatics) {
        var section = rtr.Find(208);
        if (section.Length != 0)
            throw new NotSupportedException("ThreadStaticOffsetRegion (208) has no established grammar.");

        section = rtr.Find(310);
        var data = section.Length == 0 ? default : image.FileSpan(section.Start, checked((int)section.Length));
        var table = new NativeTable(data);
        while (table.MoveNext()) {
            var reader = new NativeReader(data, table.Vertex);
            uint type = reader.Unsigned(), location = reader.Unsigned();
            if (type >= common.Length || common[(int)type] == 0 || location >= common.Length || common[(int)location] == 0)
                throw new InvalidDataException("Class constructor map refers outside CommonFixups or to null.");

            StaticConstructor entry = new() { Vertex = table.Vertex, Type = common[(int)type], NonGcBase = common[(int)location] };
            // The map names the non-GC base
            // Its preceding pointer-sized context holds zero after initialization, or an exact callable
            entry.Pointer = BinaryPrimitives.ReadUInt64LittleEndian(memory.Read(checked(entry.NonGcBase - 8), 8));
            entry.Entrypoint = entry.Pointer;
            if ((entry.Pointer & 2) != 0) {
                entry.Descriptor = entry.Pointer - 2;
                var descriptor = memory.Read(entry.Descriptor, 16);
                entry.Entrypoint = BinaryPrimitives.ReadUInt64LittleEndian(descriptor);
                entry.GenericContext = BinaryPrimitives.ReadUInt64LittleEndian(descriptor[8..]);
                if (entry.Entrypoint == 0 || entry.GenericContext == 0 || !image.IsMapped(entry.GenericContext, 1))
                    throw new InvalidDataException("A class constructor function descriptor has no entrypoint or mapped generic context.");
            }
            if (entry.Entrypoint != 0 && !image.IsExecutable(entry.Entrypoint))
                throw new InvalidDataException("A class constructor entrypoint is outside executable storage.");

            Constructors.Add(entry);
        }

        section = rtr.Find(334);
        data = section.Length == 0 ? default : image.FileSpan(section.Start, checked((int)section.Length));
        table = new NativeTable(data);
        while (table.MoveNext()) {
            var reader = new NativeReader(data, table.Vertex);
            uint type = reader.Unsigned();
            if (type >= references.Length || references[(int)type] == 0)
                throw new InvalidDataException("StaticsInfo type refers outside NativeReferences or to null.");

            GenericStatics entry = new() { Vertex = table.Vertex, Type = references[(int)type] };
            uint seen = 0;
            while (true) {
                uint kind = reader.Unsigned();
                if (kind == 0)
                    break;

                uint flag = kind switch {
                    0x42 => 1,
                    0x43 => 2,
                    0x49 => 4,
                    _ => throw new InvalidDataException($"Unknown StaticsInfo bag kind 0x{kind:X}.")
                };
                if ((seen & flag) != 0)
                    throw new InvalidDataException("Duplicate StaticsInfo bag entry.");

                seen |= flag;
                uint index = reader.Unsigned();
                if (index >= nativeStatics.Length || nativeStatics[(int)index] == 0)
                    throw new InvalidDataException("StaticsInfo storage refers outside NativeStatics or to null.");

                ulong address = nativeStatics[(int)index];
                if (kind == 0x42)
                    entry.NonGcBase = address;
                else if (kind == 0x43)
                    entry.GcCell = address;
                else
                    entry.ThreadIndex = address;
            }

            Generics.Add(entry);
        }

        section = rtr.Find(201);
        if ((section.Length & 3) != 0)
            throw new InvalidDataException("GC static region is not an array of relative pointers.");

        data = section.Length == 0 ? default : memory.Read(section.Start, checked((int)section.Length));
        GcCells.EnsureCapacity(data.Length / 4);
        for (int offset = 0; offset < data.Length; offset += 4) {
            ulong cell = checked((ulong)((long)section.Start + offset + BinaryPrimitives.ReadInt32LittleEndian(data[offset..])));
            var bytes = memory.Read(cell, 8);
            ulong tagged = checked((ulong)((long)cell + BinaryPrimitives.ReadInt32LittleEndian(bytes)));
            if ((tagged & 1) == 0)
                throw new InvalidDataException("GC static cell is already initialized; extraction requires the original binary.");

            GcStaticCell entry = new() { Cell = cell, Descriptor = tagged & ~3UL, Flags = (byte)(tagged & 3) };
            if ((entry.Flags & 2) != 0)
                entry.PreinitData = checked((ulong)((long)cell + 4 + BinaryPrimitives.ReadInt32LittleEndian(bytes[4..])));

            GcCells.Add(entry);
        }

        section = rtr.Find(202);
        if ((section.Length & 7) != 0)
            throw new InvalidDataException("Thread static region is not an array of absolute pointers.");

        data = section.Length == 0 ? default : memory.Read(section.Start, checked((int)section.Length));
        ThreadDescriptors.EnsureCapacity(data.Length / 8);
        for (int offset = 0; offset < data.Length; offset += 8)
            ThreadDescriptors.Add(BinaryPrimitives.ReadUInt64LittleEndian(data[offset..]));

        uint pointerFlag = rtr.Major < 10 ? 0x00200000U : 0x01000000U;
        for (int i = 0; i < GcCells.Count + ThreadDescriptors.Count; ++i) {
            ulong address = i < GcCells.Count ? GcCells[i].Descriptor : ThreadDescriptors[i - GcCells.Count];
            ref int index = ref CollectionsMarshal.GetValueRefOrAddDefault(AllocationIndex, address, out bool known);
            if (known)
                continue;

            // These descriptors end after related_type
            // Vtable and hash fields belong only to ordinary MethodTables
            var bytes = memory.Read(address, 16);
            StaticAllocation allocation = new() {
                Address = address,
                Flags = BinaryPrimitives.ReadUInt32LittleEndian(bytes),
                BaseSize = BinaryPrimitives.ReadUInt32LittleEndian(bytes[4..]),
                RelatedType = BinaryPrimitives.ReadUInt64LittleEndian(bytes[8..])
            };
            uint otherFlags = allocation.Flags & ~pointerFlag;
            if (otherFlags != 0 && (rtr.Major < 10 || otherFlags != 0x50001000U))
                throw new InvalidDataException("Static allocation descriptor contains unknown flags.");
            if (allocation.BaseSize < 24 || (allocation.BaseSize & 7) != 0 || allocation.RelatedType == 0)
                throw new InvalidDataException("Invalid static allocation descriptor header.");

            if ((allocation.Flags & pointerFlag) != 0) {
                long count = BinaryPrimitives.ReadInt64LittleEndian(memory.Read(checked(address - 8), 8));
                if (count <= 0 || count > (int.MaxValue - 8) / 16)
                    throw new InvalidDataException("Invalid GCDesc count on a static allocation descriptor.");

                int length = checked(8 + (int)count * 16);
                allocation.Runs = GcLayouts.ReadObjectRuns(memory.Read(checked(address - (uint)length), length), allocation.BaseSize, Runs);
            }

            index = Allocations.Count;
            Allocations.Add(allocation);
        }

        foreach (ref readonly var cell in CollectionsMarshal.AsSpan(GcCells)) {
            if (cell.PreinitData != 0) {
                uint length = Allocations[AllocationIndex[cell.Descriptor]].BaseSize - 16;
                memory.Read(cell.PreinitData, checked((int)length));
            }
        }
    }

    public void BindFields(PeImage image, RuntimeMemory memory, ReflectionMaps maps, MethodTables types) {
        var generics = new Dictionary<ulong, int>(Generics.Count);
        for (int i = 0; i < Generics.Count; ++i) {
            var entry = Generics[i];
            if (!generics.TryAdd(entry.Type, i))
                throw new InvalidDataException("Duplicate type in StaticsInfoHashtable.");

            if (entry.ThreadIndex != 0)
                ReadThreadIndex(memory, entry.ThreadIndex, types.Types[types.Index[entry.Type]].TypeManager);
        }

        var cells = new Dictionary<ulong, int>(GcCells.Count);
        for (int i = 0; i < GcCells.Count; ++i)
            cells.TryAdd(GcCells[i].Cell, i);

        for (int i = 0; i < maps.Fields.Count; ++i) {
            ref readonly var field = ref CollectionsMarshal.AsSpan(maps.Fields)[i];
            if (field.Storage == 0)
                continue;

            StaticField entry = new() { FieldMapIndex = i, Offset = field.Value };
            if (field.Location == FieldLocation.Ordinal) {
                entry.Location = StaticLocation.Ordinal;
                Fields.Add(entry);
                continue;
            }

            ulong address = field.StaticBase;
            if (field.Location == FieldLocation.Offset && generics.TryGetValue(field.DeclaringType, out int index)) {
                ref readonly var storage = ref CollectionsMarshal.AsSpan(Generics)[index];
                address = field.Storage switch { 1 => storage.NonGcBase, 2 => storage.GcCell, _ => storage.ThreadIndex };
            }

            if (address == 0) {
                entry.Location = StaticLocation.RuntimeBase;
            } else if (field.Storage == 1) {
                entry.Location = StaticLocation.NonGcAddress;
                entry.Address = checked(address + entry.Offset);
                if (!image.IsMapped(entry.Address, 1))
                    throw new InvalidDataException("Non-GC static field is outside mapped storage.");
            } else if (field.Storage == 2) {
                if (!cells.TryGetValue(address, out int cellIndex))
                    throw new InvalidDataException("GC static field refers to a cell absent from GCStaticRegion.");

                entry.Location = StaticLocation.GcObject;
                entry.Address = address;
                entry.Descriptor = GcCells[cellIndex].Descriptor;
            } else {
                entry.Location = StaticLocation.ThreadObject;
                entry.Address = address;
                int thread = ReadThreadIndex(memory, address, types.Types[types.Index[field.DeclaringType]].TypeManager);
                entry.Descriptor = ThreadIndices[thread].Descriptor;
            }

            if (entry.Descriptor != 0) {
                ref readonly var allocation = ref CollectionsMarshal.AsSpan(Allocations)[AllocationIndex[entry.Descriptor]];
                if (entry.Offset < 8 || entry.Offset >= allocation.BaseSize - 8)
                    throw new InvalidDataException("Static field offset exceeds the allocation descriptor.");
            }

            Fields.Add(entry);
        }
    }

    private int ReadThreadIndex(RuntimeMemory memory, ulong address, ulong typeManager) {
        ref int index = ref CollectionsMarshal.GetValueRefOrAddDefault(threadIndex, address, out bool known);
        if (!known) {
            var bytes = memory.Read(address, 16);
            long storageIndex = BinaryPrimitives.ReadInt64LittleEndian(bytes[8..]);
            int slot = storageIndex < 0 ? 0 : checked((int)storageIndex);
            if (slot >= ThreadDescriptors.Count)
                throw new InvalidDataException("Thread static index exceeds ThreadStaticRegion.");

            ThreadStaticIndex entry = new() {
                Address = address,
                TypeManager = BinaryPrimitives.ReadUInt64LittleEndian(bytes),
                Index = checked((int)storageIndex),
                Descriptor = ThreadDescriptors[slot],
                InlinedOffset = storageIndex < 0 ? checked((uint)(-storageIndex - 8)) : 0
            };
            if (entry.InlinedOffset >= Allocations[AllocationIndex[entry.Descriptor]].BaseSize - 16)
                throw new InvalidDataException("Inlined thread static storage exceeds its allocation descriptor.");

            index = ThreadIndices.Count;
            ThreadIndices.Add(entry);
        }

        if (ThreadIndices[index].TypeManager != typeManager)
            throw new NotSupportedException("Thread static index refers to a different type-manager module.");

        return index;
    }
}
