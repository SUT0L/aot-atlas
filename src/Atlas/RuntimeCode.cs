using System.Globalization;
using System.Runtime.InteropServices;

namespace Atlas;

public enum RuntimeCodeKind : byte { Vtable, SealedVtable, Finalizer, EagerConstructor, ModuleInitializer }

public readonly record struct RuntimeCodeRole(ulong Target, ulong Witness, int Owner, uint Slot, RuntimeCodeKind Kind,
    bool RequiresInstantiatingThunk = false);

public sealed class RuntimeCode {
    public readonly List<RuntimeCodeRole> Roles = new();
    public readonly IndexRange[] Functions = [];
    public readonly int NameCapacity = 64;

    public RuntimeCode() { }

    public RuntimeCode(Extraction extraction) {
        var image = extraction.Image;
        var types = CollectionsMarshal.AsSpan(extraction.Types.Types);
        var pointers = CollectionsMarshal.AsSpan(extraction.Types.Pointers);
        int capacity = checked(extraction.Dispatch.Targets.Count
            + (int)(extraction.Header.Find(205).Length / 4) + (int)(extraction.Header.Find(213).Length / 4));
        // Most slots are inherited
        // Counting changed slots avoids reserving a role record for every pointer in large generic type hierarchies
        foreach (ref readonly var type in types) {
            if (type.ElementType == 0x15)
                continue;

            ReadOnlySpan<ulong> inherited = default;
            ulong inheritedFinalizer = 0;
            if (type.Kind == 0 && type.RelatedType != 0) {
                ref readonly var parent = ref types[extraction.Types.Index[type.RelatedType]];
                inherited = pointers.Slice(parent.Vtable.Start, parent.Vtable.Count);
                inheritedFinalizer = parent.Finalizer;
            }

            var slots = pointers.Slice(type.Vtable.Start, type.Vtable.Count);
            for (int slot = 0; slot < slots.Length; ++slot) {
                if (slot >= inherited.Length || slots[slot] != inherited[slot])
                    capacity = checked(capacity + 1);
            }
            if (type.Finalizer != 0 && type.Finalizer != inheritedFinalizer)
                capacity = checked(capacity + 1);
        }

        Roles.EnsureCapacity(capacity);
        for (int owner = 0; owner < types.Length; ++owner) {
            ref readonly var type = ref types[owner];
            NameCapacity = Math.Max(NameCapacity, checked(extraction.Names.Values[owner].Length + 64));
            if (type.ElementType == 0x15)
                continue;

            ReadOnlySpan<ulong> inherited = default;
            ulong inheritedFinalizer = 0;
            if (type.Kind == 0 && type.RelatedType != 0) {
                ref readonly var parent = ref types[extraction.Types.Index[type.RelatedType]];
                inherited = pointers.Slice(parent.Vtable.Start, parent.Vtable.Count);
                inheritedFinalizer = parent.Finalizer;
            }

            var slots = pointers.Slice(type.Vtable.Start, type.Vtable.Count);
            for (int slot = 0; slot < slots.Length; ++slot) {
                ulong target = slots[slot];
                if ((slot < inherited.Length && inherited[slot] == target) || !image.IsExecutable(target))
                    continue;
                Roles.Add(new RuntimeCodeRole(target, type.Address + 24 + (uint)slot * 8UL, owner + 1,
                    (uint)slot, RuntimeCodeKind.Vtable));
            }

            if (type.Finalizer != 0 && type.Finalizer != inheritedFinalizer) {
                Roles.Add(new RuntimeCodeRole(type.Finalizer, type.FinalizerCell, owner + 1, 0, RuntimeCodeKind.Finalizer));
            }
        }

        foreach (ref readonly var target in CollectionsMarshal.AsSpan(extraction.Dispatch.Targets)) {
            if (target.SealedSlot == 0)
                continue;
            ref readonly var slot = ref CollectionsMarshal.AsSpan(extraction.Dispatch.SealedSlots)[target.SealedSlot - 1];
            ref readonly var type = ref types[target.OwnerType];
            uint index = checked((uint)((slot.Address - type.SealedVtable) / 4));
            Roles.Add(new RuntimeCodeRole(slot.Target, slot.Address, target.OwnerType + 1, index, RuntimeCodeKind.SealedVtable,
                target.RequiresInstantiatingThunk));
        }

        foreach (int sectionId in new int[] { 205, 213 }) {
            var section = extraction.Header.Find(sectionId);
            var entries = RuntimeTables.Fixups(image, section);
            var kind = sectionId == 205 ? RuntimeCodeKind.EagerConstructor : RuntimeCodeKind.ModuleInitializer;
            for (int slot = 0; slot < entries.Length; ++slot) {
                if (!image.IsExecutable(entries[slot]))
                    throw new InvalidDataException($"RTR section {sectionId} has a non-executable initializer.");
                Roles.Add(new RuntimeCodeRole(entries[slot], section.Start + (uint)slot * 4UL, 0, (uint)slot, kind));
            }
        }

        Roles.Sort(static (left, right) => {
            int order = left.Target.CompareTo(right.Target);
            if (order == 0)
                order = ((byte)left.Kind).CompareTo((byte)right.Kind);
            if (order == 0)
                order = left.Witness.CompareTo(right.Witness);
            return order != 0 ? order : left.Owner.CompareTo(right.Owner);
        });
        int count = 0, functionCount = 0;
        for (int i = 0; i < Roles.Count; ++i) {
            if (i == 0 || Roles[i] != Roles[count - 1]) {
                if (count == 0 || Roles[i].Target != Roles[count - 1].Target)
                    ++functionCount;
                Roles[count++] = Roles[i];
            }
        }
        Roles.RemoveRange(count, Roles.Count - count);

        Functions = new IndexRange[functionCount];
        int function = 0;
        for (int first = 0; first < Roles.Count;) {
            int end = first + 1;
            while (end < Roles.Count && Roles[end].Target == Roles[first].Target)
                ++end;
            Functions[function++] = new IndexRange(first, end - first);
            first = end;
        }
    }

    public static string KindName(RuntimeCodeKind kind) => kind switch {
        RuntimeCodeKind.Vtable => "vtable",
        RuntimeCodeKind.SealedVtable => "sealed_vtable",
        RuntimeCodeKind.Finalizer => "finalizer",
        RuntimeCodeKind.EagerConstructor => "eager_constructor",
        RuntimeCodeKind.ModuleInitializer => "module_initializer",
        _ => throw new ArgumentOutOfRangeException(nameof(kind))
    };

    public static int WriteName(Extraction extraction, in RuntimeCodeRole role, Span<char> destination) {
        string prefix = KindName(role.Kind);
        prefix.CopyTo(destination);
        "::".CopyTo(destination[prefix.Length..]);
        int length = prefix.Length + 2;
        if (role.Owner != 0) {
            string owner = extraction.Names.Values[role.Owner - 1];
            owner.CopyTo(destination[length..]);
            length += owner.Length;
            if (role.Kind == RuntimeCodeKind.Finalizer)
                return length;
            "::slot_".CopyTo(destination[length..]);
            length += 7;
        }
        role.Slot.TryFormat(destination[length..], out int digits, provider: CultureInfo.InvariantCulture);
        return length + digits;
    }
}
