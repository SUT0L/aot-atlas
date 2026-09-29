using System.Runtime.InteropServices;
using System.Text.Json;
using Atlas;

internal static class MethodsOutput {
    internal static void Write(Utf8JsonWriter json, string inputSha256, Extraction extraction, ManagedAbi abi, double abiSeconds) {
        var image = extraction.Image;
        var signatures = extraction.Metadata.Signatures;
        var maps = extraction.Maps;
        var generics = extraction.Generics;
        json.WriteStartObject();
        json.WriteString("input_sha256", inputSha256);
        StaticsOutput.WriteConstructors(json, extraction);
        json.WriteNumber("methods_seconds", extraction.TypesSeconds);
        json.WriteNumber("abi_seconds", abiSeconds);
        json.WriteStartArray("generic_types");
        foreach (ref readonly var entry in CollectionsMarshal.AsSpan(generics.Types)) {
            json.WriteStartArray();
            json.WriteNumberValue(entry.Vertex);
            json.WriteNumberValue(entry.MethodTable);
            json.WriteEndArray();
        }
        json.WriteEndArray();

        var renderer = new MethodText(extraction);
        json.WriteStartArray("methods");
        int count = maps.Methods.Count + generics.Methods.Count;
        for (int index = 0; index < count; ++index) {
            var entry = new MethodRecord(extraction, index);
            var text = renderer.Render(entry);
            json.WriteStartObject();
            json.WriteNumber("section", entry.Section);
            json.WriteNumber("vertex", entry.Vertex);
            json.WriteNumber("declaring_type", entry.DeclaringType);
            json.WriteNumber("entrypoint", entry.Entrypoint);
            json.WriteNumber("dictionary", entry.Dictionary);
            json.WriteNumber("invoke_stub", entry.InvokeStub);
            json.WriteNumber("flags", entry.Flags);
            json.WriteNumber("token", entry.Token);
            json.WriteNumber("metadata_offset", entry.MetadataOffset);
            json.WriteNumber("native_offset", entry.NativeOffset);
            json.WriteBoolean("async_variant", entry.AsyncVariant);
            json.WriteString("method_name", entry.Name);
            json.WriteString("name", text[..renderer.NameLength]);
            json.WriteString("declared_signature", text);
            if (entry.Dictionary != 0) {
                int templateIndex = extraction.Shared.Templates[index - maps.Methods.Count];
                json.WriteStartObject("shared_template");
                json.WriteString("source", "generic_method_template_map");
                json.WriteString("status", templateIndex > 0 ? "matched" : templateIndex < 0 ? "ambiguous" : "unresolved");
                if (templateIndex > 0) {
                    ref readonly var template = ref CollectionsMarshal.AsSpan(extraction.Templates.Methods)[templateIndex - 1];
                    json.WriteNumber("vertex", template.Vertex);
                    json.WriteNumber("layout_offset", template.LayoutOffset);
                    json.WriteNumber("entrypoint", template.Method.Entrypoint);
                    json.WriteNumber("jump_target", extraction.Shared.JumpTargets[templateIndex - 1]);
                    json.WriteBoolean("has_unboxing_flag", (template.Method.Flags & 2) != 0);
                }
                json.WriteEndObject();
            }
            json.WriteNumber("calling_convention", signatures.Methods[entry.Signature].CallingConvention);
            json.WriteString("convention_format", signatures.Methods[entry.Signature].NativeConvention ? "native_layout" : "metadata");
            json.WriteNumber("signature_offset", signatures.Methods[entry.Signature].Offset);
            ref readonly var methodAbi = ref abi.Methods[index];
            if (methodAbi.UnboxedTarget != 0) {
                json.WriteNumber("unboxed_entrypoint", methodAbi.UnboxedTarget);
                json.WriteString("unboxing_stub_bytes", Convert.ToHexStringLower(image.FileSpan(entry.Entrypoint, methodAbi.UnboxingLength)));
            }
            int returnType = methodAbi.Return.Binding;
            json.WriteNumber("return_type_address", returnType == 0 ? 0 : extraction.Types.Types[returnType - 1].Address);
            for (int kind = 0; kind < 2; ++kind) {
                json.WriteStartArray(kind == 0 ? "parameter_type_addresses" : "vararg_type_addresses");
                for (int i = methodAbi.Parameters.Start; i < methodAbi.Parameters.End; ++i) {
                    var parameter = abi.Parameters[i];
                    if (parameter.Role != (kind == 0 ? AbiRole.Parameter : AbiRole.Vararg))
                        continue;
                    int type = parameter.Value.Binding;
                    json.WriteNumberValue(type == 0 ? 0 : extraction.Types.Types[type - 1].Address);
                }
                json.WriteEndArray();
            }
            ManagedAbiOutput.Write(json, extraction, abi, index);
            if (methodAbi.UnboxedTarget != 0)
                ManagedAbiOutput.Write(json, extraction, abi, index, unboxed: true);

            json.WriteStartArray("arguments");
            foreach (ulong argument in entry.Arguments)
                json.WriteNumberValue(argument);
            json.WriteEndArray();
            json.WriteEndObject();
        }

        json.WriteEndArray();
        TemplatesOutput.Write(json, extraction, renderer);
        TraceOutput.Write(json, extraction, renderer, abi);
        json.WriteEndObject();
    }
}
