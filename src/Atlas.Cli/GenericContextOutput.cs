using System.Text.Json;
using Atlas;

internal static class GenericContextOutput {
    private static readonly string[] Registers = [
        "rax", "rcx", "rdx", "rbx", "rsp", "rbp", "rsi", "rdi",
        "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15"
    ];

    internal static void Write(
        Utf8JsonWriter json,
        string inputSha256,
        PeImage image,
        ManagedUnwind managed,
        MethodGcMap map,
        GenericContextReferences references,
        DictionarySlotConsumers consumers,
        string delegateStatus,
        string? delegateError = null) {
        json.WriteStartObject();
        json.WriteString("input_sha256", inputSha256);
        json.WriteNumber("image_base", image.ImageBase);
        json.WriteNumber("gcinfo_version", map.Version);
        json.WriteString("region_source", managed.RegionSource.ToString());
        json.WriteString("gc_headers_status", managed.RegionSource == ManagedRegionSource.Unknown ? "unavailable"
            : map.Methods.Any(method => method.Info is null) ? "partial" : "complete");
        json.WriteString("delegate_consumers_status", delegateStatus);

        if (delegateError is not null)
            json.WriteString("delegate_consumers_error", delegateError);

        json.WriteNumber("declared_method_contexts", references.DeclaredMethodContexts);
        json.WriteNumber("proven_context_parameters", references.Parameters.Length);

        json.WriteStartArray("parameters");

        for (int index = 0; index < references.Parameters.Length; ++index) {
            var parameter = references.Parameters[index];

            json.WriteStartObject();
            json.WriteNumber("index", index);
            json.WriteNumber("target", parameter.Target);
            json.WriteString("register", Registers[parameter.Register]);
            json.WriteNumber("prologue_store", parameter.Store);
            json.WriteNumber("gcinfo_rva", parameter.GcInfoRva);
            json.WriteEndObject();
        }

        json.WriteEndArray();

        var resolved = references.Parameters.Select(parameter => parameter.Target).ToHashSet();

        json.WriteStartArray("unresolved_context_parameters");

        foreach (var method in map.Methods) {
            if (method.Info is not { } info
                || (info.Flags & 0x30) != 0x20
                || resolved.Contains(image.ImageBase + method.Begin)) {
                continue;
            }

            json.WriteStartObject();
            json.WriteNumber("target", image.ImageBase + method.Begin);
            json.WriteNumber("gcinfo_rva", method.Address);
            json.WriteEndObject();
        }

        json.WriteEndArray();

        json.WriteStartArray("unavailable_gc_headers");

        foreach (var method in map.Methods) {
            if (method.Info is not null)
                continue;

            json.WriteStartObject();
            json.WriteNumber("target", image.ImageBase + method.Begin);
            json.WriteNumber("gcinfo_rva", method.Address);
            json.WriteString("error", method.Error);
            json.WriteEndObject();
        }

        json.WriteEndArray();

        json.WriteStartArray("unresolved_control_flow_owners");

        foreach (ulong owner in references.UnresolvedControlFlowOwners)
            json.WriteNumberValue(owner);

        json.WriteEndArray();

        json.WriteStartArray("references");

        foreach (var reference in references.Values) {
            json.WriteStartObject();
            json.WriteNumber("instruction", reference.Instruction);
            json.WriteNumber("target", reference.Target);
            json.WriteNumber("method_dictionary", reference.Context);
            DictionaryContextOutput.WriteEvidence(json, reference.Evidence);
            json.WriteNumber("parameter", reference.ParameterIndex);
            json.WriteEndObject();
        }

        json.WriteEndArray();
        DictionaryContextOutput.Write(json, consumers);
        json.WriteEndObject();
    }
}
