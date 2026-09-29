using System.Runtime.InteropServices;
using System.Text.Json;
using Atlas;

internal static class StaticsOutput {
    internal static void WriteConstructors(Utf8JsonWriter json, Extraction extraction) {
        json.WriteStartArray("constructors");
        foreach (ref readonly var entry in CollectionsMarshal.AsSpan(extraction.Statics.Constructors)) {
            json.WriteStartObject();
            json.WriteNumber("vertex", entry.Vertex);
            json.WriteNumber("type", entry.Type);
            json.WriteString("name", extraction.Names.Values[extraction.Types.Index[entry.Type]]);
            json.WriteNumber("nongc_base", entry.NonGcBase);
            json.WriteNumber("context", entry.NonGcBase - 8);
            json.WriteNumber("encoded_pointer", entry.Pointer);
            json.WriteNumber("descriptor", entry.Descriptor);
            json.WriteNumber("entrypoint", entry.Entrypoint);
            json.WriteNumber("generic_context", entry.GenericContext);
            json.WriteEndObject();
        }
        json.WriteEndArray();
    }

    internal static void Write(Utf8JsonWriter json, string inputSha256, Extraction extraction) {
        var statics = extraction.Statics;
        json.WriteStartObject();
        json.WriteString("input_sha256", inputSha256);
        WriteConstructors(json, extraction);

        json.WriteStartArray("generic_statics");
        foreach (ref readonly var entry in CollectionsMarshal.AsSpan(statics.Generics)) {
            json.WriteStartObject();
            json.WriteNumber("vertex", entry.Vertex);
            json.WriteNumber("type", entry.Type);
            json.WriteString("name", extraction.Names.Values[extraction.Types.Index[entry.Type]]);
            json.WriteNumber("nongc_base", entry.NonGcBase);
            json.WriteNumber("gc_cell", entry.GcCell);
            json.WriteNumber("thread_index", entry.ThreadIndex);
            json.WriteEndObject();
        }
        json.WriteEndArray();

        json.WriteStartArray("gc_cells");
        foreach (ref readonly var entry in CollectionsMarshal.AsSpan(statics.GcCells)) {
            json.WriteStartArray();
            json.WriteNumberValue(entry.Cell);
            json.WriteNumberValue(entry.Descriptor);
            json.WriteNumberValue(entry.Flags);
            json.WriteNumberValue(entry.PreinitData);
            json.WriteEndArray();
        }
        json.WriteEndArray();

        json.WriteStartArray("thread_descriptors");
        foreach (ulong address in CollectionsMarshal.AsSpan(statics.ThreadDescriptors))
            json.WriteNumberValue(address);
        json.WriteEndArray();

        json.WriteStartArray("allocations");
        foreach (ref readonly var allocation in CollectionsMarshal.AsSpan(statics.Allocations)) {
            json.WriteStartObject();
            json.WriteNumber("address", allocation.Address);
            json.WriteString("name", $"static_storage_ref_{allocation.Address:X}");
            json.WriteNumber("flags", allocation.Flags);
            json.WriteNumber("base_size", allocation.BaseSize);
            json.WriteNumber("related_type", allocation.RelatedType);
            json.WriteStartArray("gc_runs");
            for (int i = allocation.Runs.Start; i < allocation.Runs.End; ++i) {
                ref readonly var run = ref CollectionsMarshal.AsSpan(statics.Runs)[i];
                json.WriteStartArray();
                json.WriteNumberValue(run.Offset);
                json.WriteNumberValue(run.Count);
                json.WriteNumberValue(run.EncodedSize);
                json.WriteEndArray();
            }
            json.WriteEndArray();
            json.WriteEndObject();
        }
        json.WriteEndArray();
        json.WriteStartArray("thread_indices");
        foreach (ref readonly var entry in CollectionsMarshal.AsSpan(statics.ThreadIndices)) {
            json.WriteStartObject();
            json.WriteNumber("address", entry.Address);
            json.WriteNumber("type_manager", entry.TypeManager);
            json.WriteNumber("index", entry.Index);
            json.WriteNumber("inlined_offset", entry.InlinedOffset);
            json.WriteNumber("descriptor", entry.Descriptor);
            json.WriteEndObject();
        }
        json.WriteEndArray();

        json.WriteStartArray("fields");
        foreach (ref readonly var entry in CollectionsMarshal.AsSpan(statics.Fields)) {
            ref readonly var field = ref CollectionsMarshal.AsSpan(extraction.Maps.Fields)[entry.FieldMapIndex];
            json.WriteStartObject();
            json.WriteNumber("field_map_vertex", field.Vertex);
            json.WriteNumber("declaring_type", field.DeclaringType);
            json.WriteString("field_name", field.Name);
            json.WriteString("name", $"{extraction.Names.Values[extraction.Types.Index[field.DeclaringType]]}::{field.Name}");
            json.WriteNumber("storage", field.Storage);
            json.WriteBoolean("is_init_only", (field.Flags & 0x80) != 0);
            json.WriteString("location", entry.Location.ToString());
            json.WriteNumber("address", entry.Address);
            json.WriteNumber("descriptor", entry.Descriptor);
            json.WriteNumber(entry.Location == StaticLocation.Ordinal ? "ordinal" : "offset", entry.Offset);
            json.WriteEndObject();
        }
        json.WriteEndArray();
        json.WriteEndObject();
    }
}
