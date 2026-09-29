using System.Runtime.InteropServices;
using System.Text.Json;
using Atlas;

internal static class TypesOutput {
    internal static void Write(Utf8JsonWriter json, string inputSha256, MethodTables tables, GcLayouts gc, RuntimeNames names, PeImage image, double seconds) {
        json.WriteStartObject();
        json.WriteString("input_sha256", inputSha256);
        json.WriteNumber("types_seconds", seconds);
        json.WriteStartObject("types");

        for (int index = 0; index < tables.Types.Count; ++index) {
            ref readonly var type = ref CollectionsMarshal.AsSpan(tables.Types)[index];
            json.WriteStartObject(type.Address.ToString());
            json.WriteString("name", names.Values[index]);
            json.WriteBoolean("name_complete", names.Complete[index]);
            json.WriteString("source", type.Evidence.ToString());
            json.WriteNumber("flags", type.Flags);
            json.WriteNumber("base_size", type.BaseSize);
            json.WriteNumber("related_type", type.RelatedType);
            json.WriteNumber("hash", type.Hash);
            json.WriteNumber("kind", type.Kind);
            json.WriteNumber("element_type", type.ElementType);
            json.WriteNumber("value_padding", type.ValuePadding);
            json.WriteNumber("value_size", type.ValueSize);
            json.WriteNumber("nullable_offset", type.NullableOffset);
            json.WriteBoolean("byref_like", type.ByrefLike);

            json.WriteNumber("type_manager", type.TypeManager);
            json.WriteNumber("writable_data", type.WritableData);
            json.WriteNumber("dispatch_map", type.DispatchMap);
            json.WriteNumber("finalizer", type.Finalizer);
            json.WriteNumber("sealed_vtable", type.SealedVtable);
            json.WriteNumber("generic_definition", type.GenericDefinition);
            json.WriteNumber("composition", type.Composition);
            json.WriteNumber("generic_arity", type.GenericArity);

            json.WriteStartArray("vtable");
            for (int i = type.Vtable.Start; i < type.Vtable.End; ++i)
                json.WriteNumberValue(tables.Pointers[i]);
            json.WriteEndArray();

            json.WriteStartArray("interfaces");
            for (int i = type.Interfaces.Start; i < type.Interfaces.End; ++i)
                json.WriteNumberValue(tables.Pointers[i]);
            json.WriteEndArray();

            json.WriteStartArray("arguments");
            for (int i = type.Arguments.Start; i < type.Arguments.End; ++i)
                json.WriteNumberValue(tables.Pointers[i]);
            json.WriteEndArray();

            json.WriteStartArray("variance");
            for (int i = type.Variance.Start; i < type.Variance.End; ++i)
                json.WriteNumberValue(tables.Variances[i]);
            json.WriteEndArray();

            json.WriteEndObject();
        }

        json.WriteEndObject();

        json.WriteStartObject("gc_layouts");
        foreach (ref readonly var layout in CollectionsMarshal.AsSpan(gc.Layouts)) {
            json.WriteStartObject(tables.Types[layout.TypeIndex].Address.ToString());
            json.WriteNumber("series_count", layout.SeriesCount);
            json.WriteNumber("repeat_stride", layout.RepeatStride);
            json.WriteStartArray("runs");

            for (int i = layout.Runs.Start; i < layout.Runs.End; ++i) {
                ref readonly var run = ref CollectionsMarshal.AsSpan(gc.Runs)[i];
                json.WriteStartArray();
                json.WriteNumberValue(run.Offset);
                json.WriteNumberValue(run.Count);
                json.WriteNumberValue(run.EncodedSize);
                json.WriteEndArray();
            }

            json.WriteEndArray();
            json.WriteEndObject();
        }
        json.WriteEndObject();

        json.WriteStartObject("gc_unavailable");
        foreach (int index in CollectionsMarshal.AsSpan(gc.Unproven))
            json.WriteString(tables.Types[index].Address.ToString(), "construction_unproven");
        json.WriteEndObject();

        json.WriteEndObject();
    }
}
