using System.Buffers;
using System.Buffers.Text;
using System.Runtime.InteropServices;
using System.Text;

namespace Atlas.Binja;

internal struct DispatchAnnotation {
    internal uint Address, Witness, Owner;
    internal int Record;
    internal bool Data, Virtual;
    internal readonly ulong Key => ((ulong)Owner << 32) | Witness;
}

internal sealed class DispatchRecords {
    internal readonly DispatchAnnotation[] Sites;
    internal readonly uint[] EntryRvas;
    internal readonly int BufferLength, MaximumGroup;

    internal DispatchRecords(Extraction extraction) {
        var dispatch = extraction.Dispatch;
        ulong imageBase = extraction.Image.ImageBase;
        EntryRvas = new uint[dispatch.Entries.Count];
        foreach (ref readonly var map in CollectionsMarshal.AsSpan(dispatch.Maps)) {
            uint address = checked((uint)(map.Address - imageBase) + 8);
            int instanceEnd = map.Entries.Start + map.StandardCount + map.DefaultCount;
            for (int i = map.Entries.Start; i < map.Entries.End; ++i) {
                EntryRvas[i] = address;
                address = checked(address + (i < instanceEnd ? 6U : 8U));
            }
        }

        int unresolvedStart = dispatch.Targets.Count;
        int virtualStart = checked(unresolvedStart + dispatch.Unresolved.Count);
        Sites = new DispatchAnnotation[checked(virtualStart + extraction.Virtuals.Entries.Count)];
        ulong virtualMap = extraction.Header.Find(307).Start;
        for (int i = 0; i < Sites.Length; ++i) {
            ref var site = ref Sites[i];
            if (i < unresolvedStart) {
                ref readonly var target = ref CollectionsMarshal.AsSpan(dispatch.Targets)[i];
                site.Address = checked((uint)(target.Target - imageBase));
                site.Witness = EntryRvas[target.Entry];
                site.Owner = checked((uint)(extraction.Types.Types[target.OwnerType].Address - imageBase));
                site.Record = i;
            } else if (i < virtualStart) {
                ref readonly var entry = ref CollectionsMarshal.AsSpan(dispatch.Unresolved)[i - unresolvedStart];
                site.Address = site.Witness = EntryRvas[entry.Entry];
                site.Owner = checked((uint)(extraction.Types.Types[entry.OwnerType].Address - imageBase));
                site.Record = i - unresolvedStart;
                site.Data = true;
            } else {
                int index = i - virtualStart;
                ref readonly var entry = ref CollectionsMarshal.AsSpan(extraction.Virtuals.Entries)[index];
                ref readonly var slot = ref CollectionsMarshal.AsSpan(extraction.Virtuals.Slots)[index];
                site.Witness = checked((uint)(virtualMap + (uint)entry.Vertex - imageBase));
                site.Address = slot.Target == 0 ? site.Witness : checked((uint)(slot.Target - imageBase));
                site.Record = index;
                site.Data = slot.Target == 0;
                site.Virtual = true;
            }
        }

        // Shared bodies can serve thousands of owner/interface pairs
        // Group by destination so the cores existing tag list is read only once
        Array.Sort(Sites, static (a, b) => {
            int order = a.Data.CompareTo(b.Data);
            if (order == 0)
                order = a.Address.CompareTo(b.Address);
            return order != 0 ? order : a.Key.CompareTo(b.Key);
        });
        int group = 0;
        for (int i = 0; i < Sites.Length; ++i) {
            if (i == 0 || Sites[i].Data != Sites[i - 1].Data || Sites[i].Address != Sites[i - 1].Address)
                group = 0;
            MaximumGroup = Math.Max(MaximumGroup, ++group);
        }

        int typeLength = 0, methodLength = 0;
        foreach (string name in extraction.Names.Values)
            typeLength = Math.Max(typeLength, name.Length);
        foreach (ref readonly var entry in CollectionsMarshal.AsSpan(extraction.Virtuals.Entries)) {
            if (entry.Identity.Name.Contains('\0'))
                throw new InvalidDataException("A virtual method name contains a NUL and cant be represented by native annotations.");
            methodLength = Math.Max(methodLength, entry.Identity.Name.Length);
        }
        BufferLength = checked(Encoding.UTF8.GetMaxByteCount(Math.Max(3 * typeLength, typeLength + methodLength)) + 256);
    }

    internal static int WriteText(Extraction extraction, in DispatchAnnotation site, Span<byte> output) {
        "dispatch::"u8.CopyTo(output);
        Utf8Formatter.TryFormat(site.Owner, output[10..], out _, new StandardFormat('X', 8));
        output[18] = (byte)':';
        Utf8Formatter.TryFormat(site.Witness, output[19..], out _, new StandardFormat('X', 8));
        "::"u8.CopyTo(output[27..]);
        int length = 29;
        if (site.Virtual) {
            ref readonly var entry = ref CollectionsMarshal.AsSpan(extraction.Virtuals.Entries)[site.Record];
            ref readonly var slot = ref CollectionsMarshal.AsSpan(extraction.Virtuals.Slots)[site.Record];
            "virtual::"u8.CopyTo(output[length..]);
            length += 9;
            length += Encoding.UTF8.GetBytes(extraction.Names.Values[extraction.Types.Index[entry.DeclaringType]], output[length..]);
            "::"u8.CopyTo(output[length..]);
            length += 2;
            length += Encoding.UTF8.GetBytes(entry.Identity.Name, output[length..]);
            if (entry.Generic) {
                "::generic"u8.CopyTo(output[length..]);
                length += 9;
            } else {
                "::slot["u8.CopyTo(output[length..]);
                length += 7;
                Utf8Formatter.TryFormat(entry.Slot, output[length..], out int digits);
                length += digits;
                output[length++] = (byte)']';
            }
            "::status["u8.CopyTo(output[length..]);
            length += 9;
            ReadOnlySpan<byte> status = slot.Status switch {
                VirtualSlotStatus.Resolved => "Resolved"u8,
                VirtualSlotStatus.Generic => "Generic"u8,
                VirtualSlotStatus.NullImplementation => "NullImplementation"u8,
                VirtualSlotStatus.NonExecutable => "NonExecutable"u8,
                _ => "MissingLayout"u8
            };
            status.CopyTo(output[length..]);
            length += status.Length;
            output[length++] = (byte)']';
            if (slot.RequiresInstantiatingThunk) {
                "::instantiating_thunk"u8.CopyTo(output[length..]);
                length += 21;
            }
        } else {
            var dispatch = extraction.Dispatch;
            int owner, index;
            ulong context = 0;
            bool thunk = false;
            if (site.Data) {
                var unresolved = dispatch.Unresolved[site.Record];
                owner = unresolved.OwnerType;
                index = unresolved.Entry;
            } else {
                ref readonly var target = ref CollectionsMarshal.AsSpan(dispatch.Targets)[site.Record];
                owner = target.OwnerType;
                index = target.Entry;
                context = target.GenericContext;
                thunk = target.RequiresInstantiatingThunk;
            }
            ref readonly var entry = ref CollectionsMarshal.AsSpan(dispatch.Entries)[index];
            ReadOnlySpan<byte> kind = entry.Kind switch {
                DispatchKind.Standard => "standard::"u8,
                DispatchKind.Default => "default::"u8,
                DispatchKind.Static => "static::"u8,
                _ => "static_default::"u8
            };
            kind.CopyTo(output[length..]);
            length += kind.Length;
            length += Encoding.UTF8.GetBytes(extraction.Names.Values[owner], output[length..]);
            "::"u8.CopyTo(output[length..]);
            length += 2;
            var table = extraction.Types.Types[owner];
            ulong contract = extraction.Types.Pointers[table.Interfaces.Start + entry.InterfaceIndex];
            length += Encoding.UTF8.GetBytes(contract == 0 ? "??" : extraction.Names.Values[extraction.Types.Index[contract]], output[length..]);
            "::slot["u8.CopyTo(output[length..]);
            length += 7;
            Utf8Formatter.TryFormat(entry.InterfaceSlot, output[length..], out int digits);
            length += digits;
            output[length++] = (byte)']';
            if (context != 0) {
                "::context["u8.CopyTo(output[length..]);
                length += 10;
                length += Encoding.UTF8.GetBytes(extraction.Names.Values[extraction.Types.Index[context]], output[length..]);
                output[length++] = (byte)']';
            }
            if (thunk) {
                "::instantiating_thunk"u8.CopyTo(output[length..]);
                length += 21;
            }
            if (site.Data) {
                "::unresolved["u8.CopyTo(output[length..]);
                length += 13;
                ReadOnlySpan<byte> status = dispatch.Unresolved[site.Record].Status switch {
                    DispatchStatus.UnknownInterface => "UnknownInterface"u8,
                    DispatchStatus.UnknownContext => "UnknownContext"u8,
                    DispatchStatus.NullImplementation => "NullImplementation"u8,
                    DispatchStatus.NonExecutable => "NonExecutable"u8,
                    DispatchStatus.Reabstraction => "Reabstraction"u8,
                    _ => "Diamond"u8
                };
                status.CopyTo(output[length..]);
                length += status.Length;
                output[length++] = (byte)']';
            }
        }
        output[length] = 0;
        return length;
    }
}
