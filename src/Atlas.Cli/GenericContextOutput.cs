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
        GenericContextResult result) {
        var managed = result.Managed;
        var map = result.Gc;
        var references = result.References;
        var consumers = result.Consumers;
        json.WriteStartObject();
        json.WriteString("input_sha256", inputSha256);
        json.WriteNumber("image_base", image.ImageBase);
        json.WriteNumber("gcinfo_version", map.Version);
        json.WriteString("region_source", managed.RegionSource.ToString());
        json.WriteString("status", result.Status);
        json.WriteString("gc_headers_status", result.GcHeadersStatus);
        json.WriteString("delegate_consumers_status", result.DelegateConsumersStatus);

        if (result.DelegateConsumersError is not null)
            json.WriteString("delegate_consumers_error", result.DelegateConsumersError);

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

        json.WriteStartArray("unresolved_context_parameters");

        foreach (var method in result.UnresolvedParameters) {
            json.WriteStartObject();
            json.WriteNumber("target", image.ImageBase + method.Begin);
            json.WriteNumber("gcinfo_rva", method.Address);
            json.WriteEndObject();
        }

        json.WriteEndArray();

        json.WriteStartArray("unavailable_gc_headers");

        foreach (var method in result.UnavailableHeaders) {
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

        json.WriteStartArray("unresolved_dictionary_owners");
        foreach (ulong owner in consumers.UnresolvedOwners)
            json.WriteNumberValue(owner);
        json.WriteEndArray();

        json.WriteStartArray("dictionary_consumer_failures");
        foreach (var failure in consumers.Failures) {
            json.WriteStartObject();
            json.WriteNumber("owner", failure.Owner);
            json.WriteNumber("dictionary", failure.Dictionary);
            json.WriteNumber("instruction", failure.Instruction);
            json.WriteString("error", failure.Error);
            json.WriteEndObject();
        }
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
