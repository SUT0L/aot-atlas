using System.Runtime.InteropServices;
using System.Text.Json;
using Atlas;

internal static class TypesOutput {
    internal static void Write(Utf8JsonWriter json, string inputSha256, Extraction extraction) {
        var tables = extraction.Types;
        var gc = extraction.Gc;
        var names = extraction.Names;
        var image = extraction.Image;
        json.WriteStartObject();
        json.WriteString("input_sha256", inputSha256);
        ExtractionStatusOutput.Write(json, extraction);
        json.WriteNumber("type_preparation_seconds", extraction.TypesSeconds);

        json.WriteStartObject("types");

        for (int index = 0; index < tables.Types.Count; ++index) {
            ref readonly var type = ref CollectionsMarshal.AsSpan(tables.Types)[index];

            json.WriteStartObject(type.Address.ToString());
            JsonOutput.WriteString(json, "name", names.Values[index]);
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
            json.WriteString("source", layout.Source switch {
                GcLayoutSource.ExactValueShape => "exact_value_shape",
                GcLayoutSource.ExactArrayShape => "exact_array_shape",
                GcLayoutSource.ExactArrayElementShape => "exact_array_element_shape",
                GcLayoutSource.ExactObjectShape => "exact_object_shape",
                GcLayoutSource.ExactInheritedShape => "exact_inherited_shape",
                _ => "descriptor"
            });
            json.WriteBoolean("construction_proven", layout.Source == GcLayoutSource.Descriptor);
            if (layout.SeriesCount is long seriesCount)
                json.WriteNumber("series_count", seriesCount);
            else
                json.WriteNull("series_count");
            json.WriteNumber("repeat_stride", layout.RepeatStride);

            json.WriteStartArray("runs");

            for (int i = layout.Runs.Start; i < layout.Runs.End; ++i) {
                ref readonly var run = ref CollectionsMarshal.AsSpan(gc.Runs)[i];

                json.WriteStartArray();
                json.WriteNumberValue(run.Offset);
                json.WriteNumberValue(run.Count);
                if (run.EncodedSize is long encodedSize)
                    json.WriteNumberValue(encodedSize);
                else
                    json.WriteNullValue();
                json.WriteEndArray();
            }

            json.WriteEndArray();
            json.WriteEndObject();
        }

        json.WriteEndObject();

        json.WriteStartObject("inherited_gc");

        foreach (ref readonly var inherited in CollectionsMarshal.AsSpan(gc.Inherited)) {
            json.WriteStartObject(tables.Types[inherited.TypeIndex].Address.ToString());
            json.WriteNumber("base_type", tables.Types[inherited.BaseTypeIndex].Address);
            json.WriteStartArray("runs");

            for (int i = inherited.Runs.Start; i < inherited.Runs.End; ++i) {
                ref readonly var run = ref CollectionsMarshal.AsSpan(gc.Runs)[i];
                json.WriteStartArray();
                json.WriteNumberValue(run.Offset);
                json.WriteNumberValue(run.Count);
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
