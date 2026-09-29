using System.Runtime.InteropServices;

namespace Atlas;

public enum VirtualSlotStatus : byte {
    MissingLayout, Resolved, Generic, NullImplementation, NonExecutable
}

public struct VirtualSlot {
    public ulong DeclaringType, TargetCell, Target;
    public bool RequiresInstantiatingThunk;
    public VirtualSlotStatus Status;
}

public struct VirtualMethodEntry {
    public ulong DeclaringType;
    public int Vertex;
    public uint Token, HierarchyDistance;
    public ushort Slot;
    public bool Generic;
    public MethodIdentity Identity;
}

public sealed class VirtualMap {
    public readonly List<VirtualMethodEntry> Entries = new(8192);
    public readonly List<VirtualSlot> Slots = new(8192);

    public void Read(PeImage image, ReadyToRun rtr, Metadata metadata, NativeLayout layout, ReadOnlySpan<ulong> fixups, MapFormat format) {
        var section = rtr.Find(307);
        var data = section.Length == 0 ? default : image.FileSpan(section.Start, checked((int)section.Length));
        var table = new NativeTable(data);

        while (table.MoveNext()) {
            var reader = new NativeReader(data, table.Vertex);
            uint index = reader.Unsigned();
            if (index >= fixups.Length || fixups[(int)index] == 0)
                throw new InvalidDataException("VirtualInvokeMap refers outside CommonFixups or to null.");

            VirtualMethodEntry entry = new() {
                Vertex = table.Vertex,
                DeclaringType = fixups[(int)index],
                Token = reader.Unsigned()
            };
            uint hierarchy = reader.Unsigned();
            entry.Generic = (hierarchy & 1) != 0;
            entry.HierarchyDistance = hierarchy >> 1;
            if (!entry.Generic)
                entry.Slot = checked((ushort)reader.Unsigned());

            entry.Identity = MethodIdentity.Read(entry.Token, metadata, layout, format);
            Entries.Add(entry);
        }
    }

    public void Bind(PeImage image, RuntimeMemory memory, MethodTables tables, Dispatch dispatch) {
        var types = CollectionsMarshal.AsSpan(tables.Types);
        var pointers = CollectionsMarshal.AsSpan(tables.Pointers);
        Slots.EnsureCapacity(Entries.Count);

        foreach (ref readonly var entry in CollectionsMarshal.AsSpan(Entries)) {
            int owner = tables.Index[entry.DeclaringType];
            int current = owner;
            if (entry.HierarchyDistance >= types.Length)
                throw new InvalidDataException("VirtualInvokeMap hierarchy distance exceeds the type graph.");

            for (int step = 0; step < entry.HierarchyDistance; ++step) {
                ref readonly var type = ref types[current];
                if (type.Kind != 0 || type.RelatedType == 0)
                    throw new InvalidDataException("VirtualInvokeMap hierarchy distance exceeds the class hierarchy.");

                current = tables.Index[type.RelatedType];
            }

            ref readonly var slotType = ref types[current];
            VirtualSlot slot = new() { DeclaringType = slotType.Address };
            if (entry.Generic) {
                slot.Status = VirtualSlotStatus.Generic;
            } else if (entry.Slot < slotType.Vtable.Count) {
                ref readonly var targetType = ref types[owner];
                if (entry.Slot < targetType.Vtable.Count) {
                    slot.TargetCell = targetType.Address + 24 + entry.Slot * 8UL;
                    ulong target = pointers[targetType.Vtable.Start + entry.Slot];
                    if (target == 0)
                        slot.Status = VirtualSlotStatus.NullImplementation;
                    else if (!image.IsExecutable(target))
                        slot.Status = VirtualSlotStatus.NonExecutable;
                    else {
                        slot.Target = target;
                        slot.Status = VirtualSlotStatus.Resolved;
                    }
                }
            } else if (slotType.SealedVtable != 0) {
                slot.TargetCell = checked(slotType.SealedVtable + (uint)(entry.Slot - slotType.Vtable.Count) * 4UL);
                int index = dispatch.ReadSealedSlot(image, memory, slot.TargetCell) - 1;
                ref readonly var sealedSlot = ref CollectionsMarshal.AsSpan(dispatch.SealedSlots)[index];
                slot.Target = sealedSlot.Target;
                slot.RequiresInstantiatingThunk = sealedSlot.Flags != 0;
                slot.Status = slot.Target != 0 ? VirtualSlotStatus.Resolved : VirtualSlotStatus.NonExecutable;
            }

            Slots.Add(slot);
        }
    }
}
