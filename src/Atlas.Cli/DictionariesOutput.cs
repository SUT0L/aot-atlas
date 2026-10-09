using System.Runtime.InteropServices;
using System.Text.Json;
using Atlas;

internal static class DictionariesOutput {
    internal static void Write(Utf8JsonWriter json, string inputSha256, Extraction extraction) {
        var dictionaries = extraction.Dictionaries;
        var signatures = extraction.Signatures;

        var renderer = new MethodText(extraction);
        ulong nativeLayout = extraction.Header.Find(RtrSectionId.NativeLayoutInfo).Start;

        json.WriteStartObject();
        json.WriteString("input_sha256", inputSha256);
        ExtractionStatusOutput.Write(json, extraction.Stages, extraction.DictionarySignatureGaps);
        json.WriteString("source", "native_layout_dictionary");
        json.WriteNumber("image_base", extraction.Image.ImageBase);
        json.WriteNumber("native_layout", nativeLayout);
        json.WriteNumber("pointer_size", 8);

        json.WriteStartArray("layouts");

        foreach (ref readonly var layout in CollectionsMarshal.AsSpan(dictionaries.Layouts)) {
            json.WriteStartObject();
            json.WriteNumber("offset", layout.Offset);
            json.WriteNumber("length", layout.Length);
            json.WriteNumber("slot_count", layout.SlotCount);
            json.WriteNumber("recipe_start", layout.Recipes.Start);
            json.WriteNumber("recipe_count", layout.Recipes.Count);
            json.WriteNumber("unsupported_kind", layout.UnsupportedKind);
            json.WriteEndObject();
        }

        json.WriteEndArray();

        json.WriteStartArray("recipes");

        foreach (ref readonly var recipe in CollectionsMarshal.AsSpan(dictionaries.Recipes)) {
            json.WriteStartObject();
            json.WriteNumber("offset", recipe.Offset);
            json.WriteNumber("payload_offset", recipe.PayloadOffset);
            json.WriteNumber("length", recipe.Length);
            json.WriteNumber("kind", recipe.EncodedKind);
            json.WriteString("kind_name", recipe.Kind.ToString());

            if (recipe.Type != 0)
                JsonOutput.WriteString(json, "type", signatures.Types[recipe.Type].Render());
            if (recipe.SecondType != 0)
                JsonOutput.WriteString(json, "second_type", signatures.Types[recipe.SecondType].Render());

            if (recipe.Kind == DictionaryFixup.StaticData)
                json.WriteString("storage", recipe.Number == 1 ? "gc_cell" : "non_gc_base");
            else if (recipe.Kind == DictionaryFixup.FieldLdToken) {
                if (recipe.FieldName is not null)
                    JsonOutput.WriteString(json, "field_name", recipe.FieldName);
                else
                    json.WriteNumber("field_handle", recipe.Number);
            }
            else if (recipe.Kind is DictionaryFixup.InterfaceCall
                or DictionaryFixup.InstanceConstrainedMethod
                or DictionaryFixup.StaticConstrainedMethod
                or DictionaryFixup.LegacyConstrainedMethod
                or DictionaryFixup.LegacyDirectConstrainedMethod
                or DictionaryFixup.VTableOffset)
                json.WriteNumber("method_slot", recipe.Number);
            else if (recipe.Kind == DictionaryFixup.FieldOffset)
                json.WriteNumber("field_ordinal", recipe.Number);
            else if (recipe.Kind == DictionaryFixup.PointerToOtherSlot)
                json.WriteNumber("target_slot", recipe.Number);
            else if (recipe.Kind == DictionaryFixup.IntegerValue)
                json.WriteNumber("integer", unchecked((int)recipe.Number));
            else if (recipe.Kind == DictionaryFixup.CallingConventionConverter) {
                json.WriteNumber("converter_kind", recipe.Number);
                JsonOutput.WriteString(json, "converter_signature", signatures.MethodSignatures[recipe.ConverterSignature].Render(""));
            }

            if (recipe.Method.DeclaringType != 0) {
                json.WriteNumber("method_offset", recipe.Method.Offset);
                json.WriteNumber("method_flags", recipe.Method.Flags);
                json.WriteNumber("metadata_offset", recipe.Method.Identity.MetadataOffset);
                json.WriteNumber("native_offset", recipe.Method.Identity.NativeOffset);
                JsonOutput.WriteString(json, "declaring_type", signatures.Types[recipe.Method.DeclaringType].Render());
                JsonOutput.WriteString(json, "method_name", recipe.Method.Identity.Name);

                json.WriteStartArray("arguments");

                for (int i = recipe.Method.Arguments.Start; i < recipe.Method.Arguments.End; ++i)
                    JsonOutput.WriteStringValue(json, signatures.Types[signatures.Edges[i]].Render());

                json.WriteEndArray();
            }

            json.WriteEndObject();
        }

        json.WriteEndArray();

        json.WriteStartArray("method_templates");

        for (int i = 0; i < dictionaries.MethodLayouts.Length; ++i) {
            if (dictionaries.MethodLayouts[i] == 0)
                continue;

            ref readonly var template = ref CollectionsMarshal.AsSpan(extraction.Templates.Methods)[i];

            json.WriteStartObject();
            json.WriteNumber("template", i);
            json.WriteNumber("layout", dictionaries.MethodLayouts[i] - 1);
            json.WriteNumber("bag_offset", template.LayoutOffset);
            json.WriteNumber("witness", extraction.Header.Find(RtrSectionId.GenericMethodsTemplateMap).Start + (uint)template.Vertex);
            json.WriteEndObject();
        }

        json.WriteEndArray();

        json.WriteStartArray("type_templates");

        for (int i = 0; i < dictionaries.TypeLayouts.Length; ++i) {
            if (dictionaries.TypeLayouts[i] == 0)
                continue;

            ref readonly var template = ref CollectionsMarshal.AsSpan(extraction.Templates.Types)[i];

            json.WriteStartObject();
            json.WriteNumber("template", i);
            json.WriteNumber("layout", dictionaries.TypeLayouts[i] - 1);
            json.WriteNumber("bag_offset", template.LayoutOffset);
            json.WriteNumber("method_table", template.MethodTable);
            JsonOutput.WriteString(json, "name", extraction.Names.Values[extraction.Types.Index[template.MethodTable]]);
            json.WriteEndObject();
        }

        json.WriteEndArray();

        json.WriteStartArray("instances");

        foreach (ref readonly var instance in CollectionsMarshal.AsSpan(dictionaries.Instances)) {
            var method = new MethodRecord(extraction, extraction.Maps.Methods.Count + instance.Method);

            json.WriteStartObject();
            json.WriteNumber("dictionary", instance.Address);
            json.WriteNumber("method", instance.Method);
            JsonOutput.WriteString(json, "name", renderer.Render(method, false));
            json.WriteNumber("method_witness", extraction.Header.Find(method.Section).Start + (uint)method.Vertex);
            json.WriteNumber("template", instance.Template);

            if (instance.Layout != 0)
                json.WriteNumber("layout", instance.Layout - 1);

            json.WriteStartArray("slots");

            for (int i = instance.Slots.Start; i < instance.Slots.End; ++i) {
                ref readonly var slot = ref CollectionsMarshal.AsSpan(dictionaries.Slots)[i];
                ref readonly var recipe = ref CollectionsMarshal.AsSpan(dictionaries.Recipes)[slot.Recipe];

                json.WriteStartObject();
                json.WriteNumber("index", i - instance.Slots.Start);
                json.WriteNumber("address", slot.Address);
                json.WriteNumber("value", slot.Value);
                json.WriteNumber("recipe", slot.Recipe);
                json.WriteString("status", slot.Status.ToString());

                if (slot.Status == DictionarySlotStatus.Verified) {
                    if (slot.Type != 0) {
                        json.WriteNumber("type", extraction.Types.Types[slot.Type - 1].Address);
                        JsonOutput.WriteString(json, "type_name", extraction.Names.Values[slot.Type - 1]);
                    }

                    if (slot.Method != 0) {
                        var target = new MethodRecord(
                            extraction, extraction.Maps.Methods.Count + slot.Method - 1);

                        json.WriteNumber("target_method", slot.Method - 1);
                        JsonOutput.WriteString(json, "target_method_name", renderer.Render(target, false));
                        json.WriteNumber("target_method_witness",
                            extraction.Header.Find(target.Section).Start + (uint)target.Vertex);
                    }

                    if (slot.Cell != 0) {
                        var cell = dictionaries.InterfaceCells[slot.Cell - 1];

                        json.WriteNumber("interface_slot", cell.Slot);
                        json.WriteNumber("dispatch_cell", cell.Address);
                        json.WriteNumber("dispatch_terminator", cell.Terminator);
                        json.WriteString("dispatch_register", cell.Register == 10 ? "r10" : "r11");
                    }
                }

                json.WriteNumber("recipe_address", nativeLayout + (uint)recipe.Offset);
                json.WriteEndObject();
            }

            json.WriteEndArray();
            json.WriteEndObject();
        }

        json.WriteEndArray();
        MetadataIdentityOutput.EndObject(json, extraction.Metadata, extraction.Signatures);
    }
}
