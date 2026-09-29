using System.Runtime.InteropServices;
using System.Text.Json;
using Atlas;

internal static class CodeOutput {
    internal static void Write(Utf8JsonWriter json, string inputSha256, Extraction extraction, CodeFlow code, double seconds, long allocated) {
        var image = extraction.Image;
        json.WriteStartObject();
        json.WriteString("input_sha256", inputSha256);
        json.WriteNumber("decode_seconds", seconds);
        json.WriteNumber("allocated_bytes", allocated);
        json.WriteNumber("instruction_count", code.InstructionCount);
        var context = code.Context;
        char[] contextName = new char[context.Origins.NameCapacity];
        json.WriteNumber("unowned_call_sites", context.UnownedCallSites);
        json.WriteNumber("unowned_address_sites", context.UnownedAddressSites);
        json.WriteNumber("unproven_address_sites", context.UnprovenAddressSites);
        json.WriteStartArray("function_contexts");
        foreach (ref readonly var function in context.Functions.AsSpan()) {
            if (function.Depth == 0)
                continue;
            json.WriteStartObject();
            int length = context.WriteName(function, image.ImageBase, contextName);
            WriteContextFields(json, context, function, contextName.AsSpan(0, length));
            json.WriteEndObject();
        }
        json.WriteEndArray();
        var runtime = code.Runtime;
        char[] name = new char[runtime.NameCapacity];
        json.WriteStartArray("runtime_roles");
        foreach (ref readonly var role in CollectionsMarshal.AsSpan(runtime.Roles)) {
            json.WriteStartObject();
            json.WriteNumber("address", role.Target);
            json.WriteNumber("witness", role.Witness);
            json.WriteNumber("type", role.Owner == 0 ? 0 : extraction.Types.Types[role.Owner - 1].Address);
            json.WriteString("kind", RuntimeCode.KindName(role.Kind));
            json.WriteNumber("slot", role.Slot);
            json.WriteBoolean("requires_instantiating_thunk", role.RequiresInstantiatingThunk);
            int length = RuntimeCode.WriteName(extraction, role, name);
            json.WriteString("name", name.AsSpan(0, length));
            json.WriteEndObject();
        }
        json.WriteEndArray();
        json.WriteStartArray("entrypoints");
        foreach (ulong entrypoint in code.Entrypoints)
            json.WriteNumberValue(entrypoint);
        json.WriteEndArray();
        json.WriteStartObject("receivers");
        foreach (var receiver in code.Receivers) {
            if (receiver.Value != 0)
                json.WriteNumber(receiver.Key.ToString(), receiver.Value);
        }
        json.WriteEndObject();

        WriteEdges(json, "calls", code.Calls);
        WriteEdges(json, "jumps", code.Jumps);
        WriteEdges(json, "addresses", code.Addresses);
        json.WriteStartArray("metadata_references");
        foreach (ref readonly var reference in CollectionsMarshal.AsSpan(code.MetadataReferences)) {
            json.WriteStartObject();
            json.WriteNumber("instruction", reference.Instruction);
            json.WriteNumber("target", reference.Target);
            json.WriteStartArray("evidence");
            if ((reference.Evidence & MetadataTarget.MethodTable) != 0)
                json.WriteStringValue("methodtable");
            if ((reference.Evidence & MetadataTarget.FrozenString) != 0)
                json.WriteStringValue("frozen_string");
            if ((reference.Evidence & MetadataTarget.FrozenObject) != 0)
                json.WriteStringValue("frozen_object");
            if ((reference.Evidence & MetadataTarget.MethodDictionary) != 0)
                json.WriteStringValue("method_dictionary");
            if ((reference.Evidence & MetadataTarget.NonGcStatics) != 0)
                json.WriteStringValue("nongc_static_base");
            json.WriteEndArray();
            json.WriteEndObject();
        }
        json.WriteEndArray();

        json.WriteStartArray("receiver_accesses");
        foreach (ref readonly var field in CollectionsMarshal.AsSpan(code.ReceiverAccesses)) {
            json.WriteStartArray();
            json.WriteNumberValue(field.Type);
            json.WriteNumberValue(field.Offset);
            json.WriteNumberValue(field.Function);
            json.WriteNumberValue(field.Instruction);
            json.WriteStringValue(field.Access switch {
                MemoryAccessKind.Address => "address",
                MemoryAccessKind.Read => "read",
                MemoryAccessKind.Write => "write",
                _ => "read_write"
            });
            json.WriteEndArray();
        }
        json.WriteEndArray();
        json.WriteStartArray("field_references");
        ulong fieldMap = extraction.Header.Find(309).Start;
        foreach (ref readonly var reference in CollectionsMarshal.AsSpan(code.FieldReferences)) {
            ref readonly var access = ref CollectionsMarshal.AsSpan(code.ReceiverAccesses)[reference.AccessIndex];
            json.WriteStartObject();
            json.WriteNumber("receiver_type", access.Type);
            json.WriteNumber("offset", access.Offset);
            json.WriteNumber("function", access.Function);
            json.WriteNumber("instruction", access.Instruction);
            json.WriteNumber("size", access.Size);
            json.WriteString("access", access.Access switch {
                MemoryAccessKind.Address => "address",
                MemoryAccessKind.Read => "read",
                MemoryAccessKind.Write => "write",
                _ => "read_write"
            });
            json.WriteStartArray("evidence");
            if ((reference.Evidence & FieldTarget.FieldMap) != 0)
                json.WriteStringValue("field_map");
            if ((reference.Evidence & FieldTarget.GcDesc) != 0)
                json.WriteStringValue("gcdesc");
            if ((reference.Evidence & FieldTarget.ObjectHeader) != 0)
                json.WriteStringValue("object_header");
            json.WriteEndArray();
            json.WriteStartArray("fields");
            foreach (int index in CollectionsMarshal.AsSpan(code.FieldBindings).Slice(reference.Fields.Start, reference.Fields.Count)) {
                ref readonly var field = ref CollectionsMarshal.AsSpan(extraction.Fields.FieldTypes)[index];
                ref readonly var map = ref CollectionsMarshal.AsSpan(extraction.Maps.Fields)[field.MapIndex];
                json.WriteStartObject();
                json.WriteNumber("declaring_type", extraction.Types.Types[field.Owner - 1].Address);
                json.WriteString("name", "fieldmap::" + extraction.Names.Values[field.Owner - 1] + "::" + map.Name);
                json.WriteNumber("map_record", fieldMap + (uint)map.Vertex);
                json.WriteNumber("metadata_offset", field.MetadataOffset);
                json.WriteEndObject();
            }
            json.WriteEndArray();
            json.WriteEndObject();
        }
        json.WriteEndArray();
        json.WriteStartArray("indirect_branches");
        foreach (ulong instruction in code.IndirectBranches)
            json.WriteNumberValue(instruction);
        json.WriteEndArray();
        json.WriteEndObject();
    }

    internal static void WriteContextFields(Utf8JsonWriter json, CodeContext context, in ContextFunction function, ReadOnlySpan<char> name) {
        var origin = context.Origins.Values[function.Origin - 1];
        json.WriteNumber("address", function.Address);
        json.WriteString("name", name);
        json.WriteString("relation", CodeContext.RelationName(function.Relation));
        json.WriteNumber("source", context.Functions[function.Parent].Address);
        json.WriteNumber("anchor", origin.Address);
        json.WriteNumber("depth", function.Depth);
        json.WriteNumber("witness", function.Witness);
        json.WriteString("anchor_kind", CodeOrigins.KindName(origin.Kind));
        json.WriteNumber("anchor_witness", origin.Witness);
        json.WriteNumber("anchor_aliases", origin.Aliases);
        json.WriteString("anchor_name", context.Origins.Text.Span.Slice(origin.Name.Start, origin.Name.Count));
        if (function.Second != 0)
            json.WriteNumber("second", context.Functions[function.Second].Address);
    }

    private static void WriteEdges(Utf8JsonWriter json, string name, List<CodeEdge> edges) {
        json.WriteStartArray(name);
        foreach (ref readonly var edge in CollectionsMarshal.AsSpan(edges)) {
            json.WriteStartArray();
            json.WriteNumberValue(edge.Instruction);
            json.WriteNumberValue(edge.Target);
            json.WriteEndArray();
        }
        json.WriteEndArray();
    }
}
