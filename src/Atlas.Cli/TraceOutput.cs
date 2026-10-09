using System.Runtime.InteropServices;
using System.Text.Json;
using Atlas;

internal static class TraceOutput {
    internal static void Write(Utf8JsonWriter json, Extraction extraction, MethodText renderer, ManagedAbi abi,
        CancellationToken cancellationToken = default) {
        cancellationToken.ThrowIfCancellationRequested();
        var traces = extraction.Traces;
        var parameters = CollectionsMarshal.AsSpan(traces.ParameterNames);

        json.WriteStartArray("stack_trace");

        for (int index = 0; index < traces.Methods.Count; ++index) {
            cancellationToken.ThrowIfCancellationRequested();
            var entry = traces.Methods[index];
            var text = renderer.Render(entry);

            json.WriteStartObject();
            json.WriteNumber("offset", entry.Offset);
            json.WriteNumber("witness_rva", checked(
                extraction.Header.Find(RtrSectionId.StackTraceMethodMapping).Start + (uint)entry.Offset - extraction.Image.ImageBase));
            json.WriteNumber("entrypoint", entry.Entrypoint);
            json.WriteNumber("type_token", entry.TypeToken);
            json.WriteNumber("name_offset", entry.NameOffset);
            json.WriteNumber("signature_offset", entry.SignatureOffset);
            json.WriteNumber("parameter_names_offset", entry.ParameterNamesOffset);
            json.WriteBoolean("hidden", entry.Hidden);
            JsonOutput.WriteString(json, "declaring_type", renderer.Owner);

            int binding = extraction.Bindings.Resolve(entry.DeclaringType);

            json.WriteNumber("declaring_type_address",
                binding == 0 ? 0 : extraction.Types.Types[binding - 1].Address);
            JsonOutput.WriteString(json, "method_name", entry.Name);
            JsonOutput.WriteString(json, "name", text[..renderer.NameLength]);

            if (entry.Signature != 0) {
                JsonOutput.WriteString(json, "declared_signature", text);

                if (!renderer.SignatureComplete)
                    MetadataIdentityOutput.WriteContext(json, renderer.SignatureIndex, method: true, renderer.Context);
            }

            ManagedAbiOutput.Write(json, extraction, abi,
                extraction.Maps.Methods.Count + extraction.Generics.Methods.Count + index);

            json.WriteStartArray("generic_parameters");

            for (int i = entry.ParameterNames.Start; i < entry.ParameterNames.End; ++i) {
                cancellationToken.ThrowIfCancellationRequested();
                JsonOutput.WriteStringValue(json, parameters[i]);
            }

            json.WriteEndArray();
            json.WriteEndObject();
        }

        json.WriteEndArray();

        json.WriteStartArray("documents");

        foreach (string name in traces.Documents) {
            cancellationToken.ThrowIfCancellationRequested();
            JsonOutput.WriteStringValue(json, name);
        }

        json.WriteEndArray();

        json.WriteStartArray("line_numbers");

        foreach (ref readonly var method in CollectionsMarshal.AsSpan(traces.Lines)) {
            cancellationToken.ThrowIfCancellationRequested();
            json.WriteStartObject();
            json.WriteNumber("vertex", method.Vertex);
            json.WriteNumber("entrypoint", method.Entrypoint);

            json.WriteStartArray("points");

            for (int i = method.Points.Start; i < method.Points.End; ++i) {
                cancellationToken.ThrowIfCancellationRequested();
                ref readonly var point = ref CollectionsMarshal.AsSpan(traces.Points)[i];

                json.WriteStartArray();
                json.WriteNumberValue(point.NativeOffset);
                json.WriteNumberValue(point.Line);
                json.WriteNumberValue(point.Document);
                json.WriteEndArray();
            }

            json.WriteEndArray();
            json.WriteEndObject();
        }

        json.WriteEndArray();
    }
}
