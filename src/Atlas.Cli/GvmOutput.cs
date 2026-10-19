using System.Runtime.InteropServices;
using System.Text;
using System.Text.Json;
using Atlas;

internal static class GvmOutput {
    internal static void Write(Utf8JsonWriter json, string inputSha256, Extraction extraction) {
        var gvm = extraction.Gvms;
        var signatures = extraction.Signatures;

        var builder = new StringBuilder(256);

        json.WriteStartObject();
        json.WriteString("input_sha256", inputSha256);
        ExtractionStatusOutput.Write(json, extraction);
        json.WriteNumber("class_table", extraction.Header.Find(RtrSectionId.GenericVirtualMethodTable).Start);
        json.WriteNumber("interface_table", extraction.Header.Find(RtrSectionId.InterfaceGenericVirtualMethodTable).Start);

        json.WriteStartArray("class_rules");

        foreach (ref readonly var entry in CollectionsMarshal.AsSpan(gvm.Classes)) {
            json.WriteStartObject();
            json.WriteNumber("vertex", entry.Vertex);
            json.WriteNumber("length", entry.Length);

            json.WritePropertyName("calling");
            WriteMethod(json, extraction, entry.Calling, builder);

            json.WritePropertyName("target");
            WriteMethod(json, extraction, entry.Target, builder);
            json.WriteEndObject();
        }

        json.WriteEndArray();

        json.WriteStartArray("interface_rules");

        foreach (ref readonly var entry in CollectionsMarshal.AsSpan(gvm.Interfaces)) {
            json.WriteStartObject();
            json.WriteNumber("vertex", entry.Vertex);
            json.WriteNumber("length", entry.Length);

            json.WritePropertyName("calling");
            WriteMethod(json, extraction, entry.Calling, builder);

            json.WriteStartArray("implementations");

            for (int i = entry.Implementations.Start; i < entry.Implementations.End; ++i) {
                ref readonly var implementation = ref CollectionsMarshal.AsSpan(gvm.Implementations)[i];
                bool defaultInterface = implementation.Outcome != GvmOutcome.Method
                    || extraction.Types.Types[extraction.Types.Index[implementation.Target.Owner]].ElementType == 0x15;

                json.WriteStartObject();
                json.WriteString("outcome", implementation.Outcome.ToString());
                json.WriteBoolean("default_interface", defaultInterface);

                if (implementation.Outcome == GvmOutcome.Method) {
                    json.WritePropertyName("target");
                    WriteMethod(json, extraction, implementation.Target, builder);
                } else {
                    json.WriteNumber("error_token", implementation.Target.Token);
                }

                json.WriteStartArray("provided_types");

                for (int j = implementation.Types.Start; j < implementation.Types.End; ++j) {
                    ref readonly var type = ref CollectionsMarshal.AsSpan(gvm.Types)[j];

                    json.WriteStartObject();
                    json.WriteNumber("type", type.Type);
                    JsonOutput.WriteString(json, "name", extraction.Names.Values[extraction.Types.Index[type.Type]]);

                    json.WriteStartArray("interfaces");

                    for (int k = type.Signatures.Start; k < type.Signatures.End; ++k) {
                        ref readonly var signature = ref CollectionsMarshal.AsSpan(gvm.Signatures)[k];

                        builder.Clear();
                        signatures.Types[signature.Signature].Append(builder);

                        json.WriteStartObject();
                        json.WriteNumber("native_offset", signature.Offset);
                        JsonOutput.WriteString(json, "signature", builder.ToString());
                        json.WriteEndObject();
                    }

                    json.WriteEndArray();
                    json.WriteEndObject();
                }

                json.WriteEndArray();
                json.WriteEndObject();
            }

            json.WriteEndArray();
            json.WriteEndObject();
        }

        json.WriteEndArray();
        MetadataIdentityOutput.EndObject(json, extraction.Metadata, extraction.Signatures);
    }

    private static void WriteMethod(Utf8JsonWriter json, Extraction extraction,
        GvmMethod method, StringBuilder builder) {
        ref readonly var identity = ref method.Identity;
        var signatures = extraction.Signatures;
        string owner = extraction.Names.Values[extraction.Types.Index[method.Owner]];

        builder.Clear();
        builder.Append("gvm::")
            .Append(owner)
            .Append("::")
            .Append(identity.Name);

        json.WriteStartObject();
        json.WriteNumber("type", method.Owner);
        JsonOutput.WriteString(json, "type_name", owner);
        json.WriteNumber("token", method.Token);
        json.WriteNumber("metadata_offset", identity.MetadataOffset);
        json.WriteNumber("native_offset", identity.NativeOffset);
        JsonOutput.WriteString(json, "method_name", identity.Name);

        if (identity.Signature == 0) {
            json.WriteNull("generic_arity");
            json.WriteNull("static");
            JsonOutput.WriteString(json, "name", builder.ToString());
            json.WriteNull("declared_signature");
            json.WriteString("signature_status", "unavailable");
            json.WriteEndObject();
            return;
        }

        ref readonly var signature = ref signatures.Methods[identity.Signature];
        int arity = signature.GenericParameterCount;

        builder.Append('<');

        for (int i = 0; i < arity; ++i) {
            if (i != 0)
                builder.Append(',');

            builder.Append("TM");
            if (i != 0)
                builder.Append(i);
        }

        builder.Append('>');

        json.WriteNumber("generic_arity", arity);
        json.WriteBoolean("static", signature.NativeConvention
            ? (signature.CallingConvention & 2) != 0
            : (signature.CallingConvention & 0x20) == 0);
        JsonOutput.WriteString(json, "name", builder.ToString());

        signatures.MethodSignatures[identity.Signature].Append(builder);
        JsonOutput.WriteString(json, "declared_signature", builder.ToString());
        json.WriteEndObject();
    }
}
