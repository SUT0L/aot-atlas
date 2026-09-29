using System.Runtime.InteropServices;
using System.Text.Json;
using Atlas;

internal static class DispatchOutput {
    internal static void Write(Utf8JsonWriter json, string inputSha256, PeImage image, MethodTables tables, RuntimeNames names, Dispatch dispatch, VirtualMap virtuals, double seconds) {
        json.WriteStartObject();
        json.WriteString("input_sha256", inputSha256);
        json.WriteNumber("dispatch_seconds", seconds);
        json.WriteStartArray("maps");

        foreach (ref readonly var map in CollectionsMarshal.AsSpan(dispatch.Maps)) {
            json.WriteStartObject();
            json.WriteNumber("address", map.Address);
            json.WriteNumber("first_entry", map.Entries.Start);
            json.WriteStartArray("counts");
            json.WriteNumberValue(map.StandardCount);
            json.WriteNumberValue(map.DefaultCount);
            json.WriteNumberValue(map.StaticCount);
            json.WriteNumberValue(map.StaticDefaultCount);
            json.WriteEndArray();
            json.WriteStartArray("entries");

            for (int i = map.Entries.Start; i < map.Entries.End; ++i) {
                ref readonly var entry = ref CollectionsMarshal.AsSpan(dispatch.Entries)[i];
                json.WriteStartArray();
                json.WriteNumberValue(entry.InterfaceIndex);
                json.WriteNumberValue(entry.InterfaceSlot);
                json.WriteNumberValue(entry.ImplementationSlot);
                json.WriteNumberValue(entry.ContextSource);
                json.WriteStringValue(entry.Kind.ToString());
                json.WriteEndArray();
            }

            json.WriteEndArray();
            json.WriteEndObject();
        }
        json.WriteEndArray();

        json.WriteStartArray("virtual_methods");
        for (int i = 0; i < virtuals.Entries.Count; ++i) {
            ref readonly var entry = ref CollectionsMarshal.AsSpan(virtuals.Entries)[i];
            ref readonly var slot = ref CollectionsMarshal.AsSpan(virtuals.Slots)[i];
            json.WriteStartObject();
            json.WriteNumber("vertex", entry.Vertex);
            json.WriteNumber("declaring_type", entry.DeclaringType);
            json.WriteNumber("token", entry.Token);
            json.WriteNumber("hierarchy_distance", entry.HierarchyDistance);
            json.WriteBoolean("generic", entry.Generic);
            if (!entry.Generic)
                json.WriteNumber("slot", entry.Slot);
            json.WriteString("method_name", entry.Identity.Name);
            json.WriteString("name", $"{names.Values[tables.Index[entry.DeclaringType]]}::{entry.Identity.Name}");
            json.WriteNumber("slot_declaring_type", slot.DeclaringType);
            json.WriteNumber("target_cell", slot.TargetCell);
            json.WriteNumber("target", slot.Target);
            json.WriteBoolean("requires_instantiating_thunk", slot.RequiresInstantiatingThunk);
            json.WriteString("status", slot.Status.ToString());
            json.WriteEndObject();
        }
        json.WriteEndArray();

        json.WriteStartObject("type_maps");
        for (int i = 0; i < dispatch.TypeMaps.Length; ++i) {
            if (dispatch.TypeMaps[i] != 0)
                json.WriteNumber(tables.Types[i].Address.ToString(), dispatch.Maps[dispatch.TypeMaps[i] - 1].Address);
        }
        json.WriteEndObject();

        json.WriteStartArray("sealed_slots");
        foreach (ref readonly var slot in CollectionsMarshal.AsSpan(dispatch.SealedSlots)) {
            json.WriteStartArray();
            json.WriteNumberValue(slot.Address);
            json.WriteNumberValue(slot.EncodedTarget);
            json.WriteNumberValue(slot.Target);
            json.WriteNumberValue(slot.Flags);
            json.WriteEndArray();
        }
        json.WriteEndArray();

        json.WriteStartArray("targets");
        foreach (ref readonly var target in CollectionsMarshal.AsSpan(dispatch.Targets)) {
            ref readonly var entry = ref CollectionsMarshal.AsSpan(dispatch.Entries)[target.Entry];
            ref readonly var type = ref CollectionsMarshal.AsSpan(tables.Types)[target.OwnerType];
            json.WriteStartObject();
            json.WriteNumber("owner_type", type.Address);
            json.WriteNumber("interface_type", tables.Types[target.InterfaceType].Address);
            json.WriteNumber("interface_slot", entry.InterfaceSlot);
            json.WriteNumber("target", target.Target);
            json.WriteNumber("generic_context", target.GenericContext);
            json.WriteBoolean("requires_instantiating_thunk", target.RequiresInstantiatingThunk);
            json.WriteString("kind", entry.Kind.ToString());
            json.WriteString("name", $"{names.Values[target.OwnerType]}::dispatch::{names.Values[target.InterfaceType]}::slot_{entry.InterfaceSlot}");
            json.WriteNumber("entry_index", target.Entry);
            json.WriteNumber("target_cell", target.SealedSlot != 0 ? dispatch.SealedSlots[target.SealedSlot - 1].Address
                : type.Address + 24 + (uint)entry.ImplementationSlot * 8UL);
            json.WriteEndObject();
        }
        json.WriteEndArray();

        json.WriteStartArray("unresolved");
        foreach (ref readonly var entry in CollectionsMarshal.AsSpan(dispatch.Unresolved)) {
            json.WriteStartArray();
            json.WriteNumberValue(tables.Types[entry.OwnerType].Address);
            json.WriteNumberValue(entry.Entry);
            json.WriteStringValue(entry.Status.ToString());
            json.WriteEndArray();
        }
        json.WriteEndArray();
        json.WriteEndObject();
    }
}
