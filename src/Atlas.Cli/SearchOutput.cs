using System.Runtime.InteropServices;
using System.Text;
using System.Text.Json;
using Atlas;

internal static class SearchOutput {
    internal static int Write(Utf8JsonWriter json, string inputSha256, Extraction extraction, string query) {
        var image = extraction.Image;
        var names = extraction.Names;
        var types = CollectionsMarshal.AsSpan(extraction.Types.Types);
        var abi = new ManagedAbi(extraction);
        var code = new CodeFlow(extraction, abi);
        var strings = new NativeStrings(image, extraction.Header.Sections);
        var frozen = extraction.Frozen;
        var references = new Dictionary<ulong, int>(strings.Items.Count + frozen.Objects.Count);
        foreach (ref readonly var item in CollectionsMarshal.AsSpan(strings.Items))
            references.TryAdd(image.ImageBase + item.Rva, 0);
        foreach (ref readonly var item in CollectionsMarshal.AsSpan(frozen.Objects)) {
            if (item.Kind == FrozenKind.String)
                references.TryAdd(frozen.Start + (uint)item.Offset, 0);
        }
        foreach (ref readonly var edge in CollectionsMarshal.AsSpan(code.Addresses)) {
            ref int count = ref CollectionsMarshal.GetValueRefOrNullRef(references, edge.Target);
            if (!System.Runtime.CompilerServices.Unsafe.IsNullRef(ref count))
                ++count;
        }

        var fieldReferences = new int[extraction.Fields.FieldTypes.Count];
        foreach (int field in CollectionsMarshal.AsSpan(code.FieldBindings))
            ++fieldReferences[field];

        json.WriteStartObject();
        json.WriteString("operation", "search");
        json.WriteNumber("schema_version", 1);
        json.WriteString("input_sha256", inputSha256);
        json.WriteString("map_format", extraction.Maps.Format == MapFormat.Legacy ? "legacy" : "metadata");
        json.WriteString("query", query);
        json.WriteString("comparison", "ordinal_ignore_case");
        json.WriteStartArray("matches");
        int hits = 0;
        char[] buffer = new char[4096];
        for (int i = 0; i < types.Length; ++i) {
            if (!names.Values[i].Contains(query, StringComparison.OrdinalIgnoreCase))
                continue;

            json.WriteStartObject();
            json.WriteString("kind", "type");
            json.WriteNumber("address", types[i].Address);
            json.WriteString("name", names.Values[i]);
            json.WriteBoolean("name_complete", names.Complete[i]);
            json.WriteEndObject();
            ++hits;
        }

        var renderer = new MethodText(extraction);
        int runtimeCount = extraction.Maps.Methods.Count + extraction.Generics.Methods.Count;
        int traceEnd = runtimeCount + extraction.Traces.Methods.Count;
        int templateEnd = traceEnd + extraction.Templates.Methods.Count;
        Span<ulong> sections = stackalloc ulong[337];
        sections.Clear();
        foreach (ref readonly var section in extraction.Header.Sections.AsSpan()) {
            if ((uint)section.Id < sections.Length)
                sections[section.Id] = section.Start;
        }

        for (int i = 0; i < templateEnd; ++i) {
            ReadOnlySpan<char> text;
            int section, offset;
            ulong entrypoint, invoke = 0, unboxed = 0, dictionary = 0;
            bool hasSignature = true;
            if (i < runtimeCount) {
                var method = new MethodRecord(extraction, i);
                text = renderer.Render(method);
                section = method.Section;
                offset = method.Vertex;
                entrypoint = method.Entrypoint;
                invoke = method.InvokeStub;
                dictionary = method.Dictionary;
                unboxed = abi.Methods[i].UnboxedTarget;
            } else if (i < traceEnd) {
                ref readonly var method = ref CollectionsMarshal.AsSpan(extraction.Traces.Methods)[i - runtimeCount];
                text = renderer.Render(method);
                section = 327;
                offset = method.Offset;
                entrypoint = method.Entrypoint;
                hasSignature = method.Signature != 0;
            } else {
                ref readonly var method = ref CollectionsMarshal.AsSpan(extraction.Templates.Methods)[i - traceEnd];
                text = renderer.Render(method);
                section = 322;
                offset = method.Vertex;
                entrypoint = method.Method.Entrypoint;
            }

            var name = text[..renderer.NameLength];
            if (!name.Contains(query, StringComparison.OrdinalIgnoreCase))
                continue;

            json.WriteStartObject();
            json.WriteString("kind", "method");
            json.WriteString("name", name);
            if (hasSignature)
                json.WriteString("declared_signature", text);
            json.WriteNumber("section", section);
            json.WriteNumber("record", sections[section] + (uint)offset);
            json.WriteNumber("entrypoint", entrypoint);
            json.WriteNumber("invoke_stub", invoke);
            json.WriteNumber("dictionary", dictionary);
            json.WriteNumber("unboxed_entrypoint", unboxed);
            json.WriteEndObject();
            ++hits;
        }

        foreach (ref readonly var item in CollectionsMarshal.AsSpan(extraction.Statics.Constructors)) {
            var name = QualifiedName(names.Values[extraction.Types.Index[item.Type]], ".cctor", ref buffer);
            if (!name.Contains(query, StringComparison.OrdinalIgnoreCase))
                continue;

            json.WriteStartObject();
            json.WriteString("kind", "constructor");
            json.WriteString("name", name);
            json.WriteNumber("record", sections[310] + (uint)item.Vertex);
            json.WriteNumber("declaring_type", item.Type);
            json.WriteNumber("entrypoint", item.Entrypoint);
            json.WriteNumber("generic_context", item.GenericContext);
            json.WriteEndObject();
            ++hits;
        }

        var virtuals = extraction.Virtuals;
        for (int i = 0; i < virtuals.Entries.Count; ++i) {
            ref readonly var item = ref CollectionsMarshal.AsSpan(virtuals.Entries)[i];
            ref readonly var slot = ref CollectionsMarshal.AsSpan(virtuals.Slots)[i];
            var name = QualifiedName(names.Values[extraction.Types.Index[item.DeclaringType]], item.Identity.Name, ref buffer);
            if (!name.Contains(query, StringComparison.OrdinalIgnoreCase))
                continue;

            json.WriteStartObject();
            json.WriteString("kind", "virtual_method");
            json.WriteString("name", name);
            json.WriteNumber("record", sections[307] + (uint)item.Vertex);
            json.WriteNumber("declaring_type", item.DeclaringType);
            json.WriteNumber("target_cell", slot.TargetCell);
            json.WriteNumber("target", slot.Target);
            json.WriteBoolean("requires_instantiating_thunk", slot.RequiresInstantiatingThunk);
            json.WriteString("status", slot.Status.ToString());
            json.WriteEndObject();
            ++hits;
        }

        var marshalling = extraction.Marshalling;
        int structCount = marshalling.Structs.Count;
        for (int i = 0; i < structCount + marshalling.Delegates.Count; ++i) {
            int type, offset, section;
            ulong first, second, third;
            if (i < structCount) {
                ref readonly var item = ref CollectionsMarshal.AsSpan(marshalling.Structs)[i];
                type = item.TypeIndex;
                offset = item.Vertex;
                section = 316;
                first = item.ToNative;
                second = item.ToManaged;
                third = item.Cleanup;
            } else {
                ref readonly var item = ref CollectionsMarshal.AsSpan(marshalling.Delegates)[i - structCount];
                type = item.TypeIndex;
                offset = item.Vertex;
                section = 317;
                first = item.Open;
                second = item.Closed;
                third = item.Create;
            }
            var name = QualifiedName(i < structCount ? "native" : "delegate_marshalling", names.Values[type], ref buffer);
            if (!name.Contains(query, StringComparison.OrdinalIgnoreCase))
                continue;

            json.WriteStartObject();
            json.WriteString("kind", "marshalling");
            json.WriteString("name", name);
            json.WriteNumber("record", sections[section] + (uint)offset);
            json.WriteNumber("declaring_type", types[type].Address);
            json.WriteNumber(i < structCount ? "to_native" : "open", first);
            json.WriteNumber(i < structCount ? "to_managed" : "closed", second);
            json.WriteNumber(i < structCount ? "cleanup" : "create", third);
            json.WriteEndObject();
            ++hits;
        }

        var runtime = code.Runtime;
        if (runtime.NameCapacity > buffer.Length)
            Array.Resize(ref buffer, runtime.NameCapacity);
        foreach (ref readonly var role in CollectionsMarshal.AsSpan(runtime.Roles)) {
            int length = RuntimeCode.WriteName(extraction, role, buffer);
            var name = buffer.AsSpan(0, length);
            if (!name.Contains(query, StringComparison.OrdinalIgnoreCase))
                continue;

            json.WriteStartObject();
            json.WriteString("kind", "runtime_role");
            json.WriteString("role", RuntimeCode.KindName(role.Kind));
            json.WriteString("name", name);
            json.WriteNumber("address", role.Target);
            json.WriteNumber("witness", role.Witness);
            json.WriteNumber("declaring_type", role.Owner == 0 ? 0 : types[role.Owner - 1].Address);
            json.WriteNumber("slot", role.Slot);
            json.WriteBoolean("requires_instantiating_thunk", role.RequiresInstantiatingThunk);
            json.WriteEndObject();
            ++hits;
        }

        var context = code.Context;
        if (context.Origins.NameCapacity > buffer.Length)
            Array.Resize(ref buffer, context.Origins.NameCapacity);
        foreach (ref readonly var function in context.Functions.AsSpan()) {
            if (function.Depth == 0)
                continue;
            int length = context.WriteName(function, image.ImageBase, buffer);
            if (!buffer.AsSpan(0, length).Contains(query, StringComparison.OrdinalIgnoreCase))
                continue;

            json.WriteStartObject();
            json.WriteString("kind", "function_context");
            CodeOutput.WriteContextFields(json, context, function, buffer.AsSpan(0, length));
            json.WriteEndObject();
            ++hits;
        }

        for (int i = 0; i < extraction.Fields.FieldTypes.Count; ++i) {
            ref readonly var field = ref CollectionsMarshal.AsSpan(extraction.Fields.FieldTypes)[i];
            ref readonly var item = ref CollectionsMarshal.AsSpan(extraction.Maps.Fields)[field.MapIndex];
            int owner = field.Owner - 1;
            var name = QualifiedName(names.Values[owner], item.Name, ref buffer);
            if (!name.Contains(query, StringComparison.OrdinalIgnoreCase))
                continue;

            json.WriteStartObject();
            json.WriteString("kind", "field");
            json.WriteString("name", name);
            json.WriteString("field_name", item.Name);
            json.WriteNumber("declaring_type", types[owner].Address);
            json.WriteNumber("record", sections[309] + (uint)item.Vertex);
            json.WriteNumber("metadata_offset", field.MetadataOffset);
            json.WriteString("location", item.Location.ToString());
            json.WriteNumber(item.Location == FieldLocation.Ordinal ? "ordinal" : "offset", item.Value);
            json.WriteNumber("reference_count", fieldReferences[i]);
            json.WriteEndObject();
            ++hits;
        }

        foreach (ref readonly var item in CollectionsMarshal.AsSpan(frozen.Objects)) {
            if (item.Kind != FrozenKind.String)
                continue;
            var data = frozen.Data.Span.Slice(item.Data.Start, item.Data.Count);
            var text = MemoryMarshal.Cast<byte, char>(data);
            if (!text.Contains(query, StringComparison.OrdinalIgnoreCase))
                continue;

            ulong address = frozen.Start + (uint)item.Offset;
            json.WriteStartObject();
            json.WriteString("kind", "frozen_string");
            json.WriteNumber("address", address);
            json.WriteBase64String("utf16le", data);
            json.WriteBoolean("unpaired_surrogate", item.UnpairedSurrogate);
            if (!item.UnpairedSurrogate)
                json.WriteString("text", text);
            json.WriteNumber("reference_count", references[address]);
            json.WriteEndObject();
            ++hits;
        }

        foreach (ref readonly var item in CollectionsMarshal.AsSpan(strings.Items)) {
            var bytes = image.FileData.AsSpan(item.Data.Start, item.Data.Count);
            ReadOnlySpan<char> text;
            if (item.Wide) {
                text = MemoryMarshal.Cast<byte, char>(bytes);
            } else {
                if (bytes.Length > buffer.Length)
                    Array.Resize(ref buffer, Math.Max(bytes.Length, buffer.Length * 2));
                int length = Encoding.ASCII.GetChars(bytes, buffer);
                text = buffer.AsSpan(0, length);
            }
            if (!text.Contains(query, StringComparison.OrdinalIgnoreCase))
                continue;

            ulong address = image.ImageBase + item.Rva;
            json.WriteStartObject();
            json.WriteString("kind", "cstring");
            json.WriteNumber("address", address);
            json.WriteString("text", text);
            json.WriteString("encoding", item.Wide ? "utf-16le" : "ascii");
            json.WriteString("evidence", "nul_terminated_printable_bytes");
            json.WriteNumber("reference_count", references[address]);
            json.WriteEndObject();
            ++hits;
        }
        json.WriteEndArray();
        json.WriteNumber("match_count", hits);
        json.WriteEndObject();
        return hits;
    }

    private static ReadOnlySpan<char> QualifiedName(string owner, string member, ref char[] buffer) {
        int length = checked(owner.Length + member.Length + 2);
        if (length > buffer.Length)
            Array.Resize(ref buffer, Math.Max(length, buffer.Length * 2));
        owner.CopyTo(buffer);
        "::".CopyTo(buffer.AsSpan(owner.Length));
        member.CopyTo(buffer.AsSpan(owner.Length + 2));
        return buffer.AsSpan(0, length);
    }
}
