using System.Text.Json;
using Atlas;

internal static class FatFunctionPointersOutput {
    internal static string DescriptorUsesStatus(
        UnwindAnalysis analysis, MethodGcMap? gc, FatFunctionPointers pointers, string delegateStatus) {
        bool gcUnavailable = gc is null || analysis.Unwind is null
            || analysis.Managed?.RegionSource == ManagedRegionSource.Unknown;
        if (gcUnavailable)
            return "unavailable";

        bool gcPartial = gc!.Methods.Any(method => method.Info is null);
        bool partialUses = gcPartial || pointers.UnprovenUses.Count != 0
            || pointers.UnresolvedControlFlowOwners.Count != 0 || pointers.Failures.Count != 0
            || DictionaryConsumersStatus(pointers) != "complete"
            || delegateStatus != "complete";
        return partialUses ? "partial" : "complete";
    }

    internal static string DictionaryConsumersStatus(FatFunctionPointers pointers) =>
        pointers.DictionaryConsumers is not { } dictionaries ? "unavailable"
        : dictionaries.Failures.Count != 0 || dictionaries.UnresolvedOwners.Count != 0 ? "partial" : "complete";

    internal static void Write(
        Utf8JsonWriter json,
        string hash,
        PeImage image,
        UnwindAnalysis analysis,
        MethodGcMap? gc,
        FatFunctionPointers pointers,
        string delegateStatus,
        string? delegateError) {
        bool gcUnavailable = gc is null || analysis.Unwind is null
            || analysis.Managed?.RegionSource == ManagedRegionSource.Unknown;
        bool gcPartial = !gcUnavailable && gc!.Methods.Any(method => method.Info is null);
        JsonOutput.StartDocument(json, "fat-function-pointers");
        json.WriteString("input_sha256", hash);
        json.WriteNumber("image_base", image.ImageBase);
        json.WriteString("constructor_map_status", pointers.ConstructorMapStatus);
        json.WriteString("descriptor_uses_status", DescriptorUsesStatus(analysis, gc, pointers, delegateStatus));
        json.WriteString("gc_headers_status", gcUnavailable ? "unavailable" : gcPartial ? "partial" : "complete");
        json.WriteString("delegate_consumers_status", delegateStatus);
        if (delegateError is not null)
            json.WriteString("delegate_consumers_error", delegateError);

        json.WriteStartArray("pointers");

        for (int index = 0; index < pointers.Values.Count; ++index) {
            var pointer = pointers.Values[index];

            json.WriteStartObject();
            json.WriteNumber("index", index);
            json.WriteNumber("pointer", pointer.Pointer);
            json.WriteNumber("descriptor", pointer.Descriptor);
            json.WriteNumber("body", pointer.Body);
            json.WriteNumber("context", pointer.Context);
            json.WriteString("value_state", "initial_image");
            json.WriteString("context_role", pointer.ContextKind switch {
                FunctionPointerContextKind.MethodTable => "method_table",
                FunctionPointerContextKind.MethodDictionary => "method_dictionary",
                _ => "unknown"
            });
            json.WriteNumber("gcinfo_rva", pointer.GcInfoRva);
            json.WriteBoolean("hydrated", pointer.Hydrated);
            json.WriteEndObject();
        }

        json.WriteEndArray();

        json.WriteStartArray("references");

        foreach (var reference in pointers.References) {
            json.WriteStartObject();
            json.WriteNumber("pointer", reference.PointerIndex);
            json.WriteString("source", reference.Source switch {
                FatPointerSource.ClassConstructor => "class_constructor",
                FatPointerSource.IndirectCall => "indirect_call",
                FatPointerSource.DelegateInitializer => "delegate_initializer",
                _ => "dictionary_slot_delegate"
            });
            json.WriteNumber("owner", reference.Owner);
            json.WriteNumber("definition", reference.Definition);
            json.WriteNumber("consumer", reference.Consumer);
            json.WriteNumber("holder", reference.Holder);
            json.WriteNumber("context_load", reference.ContextLoad);
            DictionaryContextOutput.WriteEvidence(json, reference.Evidence);
            json.WriteEndObject();
        }

        json.WriteEndArray();

        var dictionaries = pointers.DictionaryConsumers;
        json.WriteStartArray("unproven_uses");
        foreach (FunctionPointerUnprovenUse use in pointers.UnprovenUses) {
            FatFunctionPointerReference reference = use.Reference;
            json.WriteStartObject();
            json.WriteNumber("pointer", reference.PointerIndex);
            json.WriteString("source", reference.Source.ToString());
            json.WriteNumber("owner", reference.Owner);
            json.WriteNumber("definition", reference.Definition);
            json.WriteNumber("consumer", reference.Consumer);
            json.WriteNumber("holder", reference.Holder);
            json.WriteNumber("context_load", reference.ContextLoad);
            DictionaryContextOutput.WriteEvidence(json, reference.Evidence);
            json.WriteString("error", use.Error);
            json.WriteEndObject();
        }
        json.WriteEndArray();

        json.WriteString("dictionary_consumers_status", DictionaryConsumersStatus(pointers));

        DictionaryContextOutput.Write(json, dictionaries);

        json.WriteStartArray("unresolved_dictionary_owners");

        if (dictionaries is not null) {
            foreach (ulong owner in dictionaries.UnresolvedOwners)
                json.WriteNumberValue(owner);
        }

        json.WriteEndArray();

        json.WriteStartArray("unresolved_control_flow_owners");

        foreach (ulong owner in pointers.UnresolvedControlFlowOwners)
            json.WriteNumberValue(owner);

        json.WriteEndArray();

        json.WriteStartArray("failures");

        foreach (var failure in pointers.Failures) {
            json.WriteStartObject();
            json.WriteString("source", failure.Source.ToString());
            json.WriteNumber("witness", failure.Witness);
            json.WriteString("error", failure.Error);
            json.WriteEndObject();
        }

        if (dictionaries is not null) {
            foreach (var failure in dictionaries.Failures) {
                json.WriteStartObject();
                json.WriteString("source", "dictionary_consumer");
                json.WriteNumber("owner", failure.Owner);
                json.WriteNumber("dictionary", failure.Dictionary);
                json.WriteNumber("instruction", failure.Instruction);
                json.WriteString("error", failure.Error);
                json.WriteEndObject();
            }
        }

        foreach (var failure in analysis.Failures) {
            json.WriteStartObject();
            json.WriteString("source", failure.Phase.ToString());
            json.WriteString("error", failure.Error);
            json.WriteEndObject();
        }

        json.WriteEndArray();
        json.WriteEndObject();
    }
}
