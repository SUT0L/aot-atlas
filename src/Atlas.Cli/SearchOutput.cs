using System.Runtime.InteropServices;
using System.Text;
using System.Text.Json;
using Atlas;

internal static class SearchOutput {
    internal static int Write(Utf8JsonWriter json, string inputSha256, AnalysisProducts products, string query) {
        var extraction = products.Extraction;
        var image = extraction.Image;
        var names = extraction.Names;
        var types = CollectionsMarshal.AsSpan(extraction.Types.Types);

        var abi = products.Abi;
        var code = products.Code;
        var strings = products.Strings!;
        var frozen = extraction.Frozen;

        var references = new Dictionary<ulong, int>(strings.Items.Count + frozen.Objects.Count);

        foreach (ref readonly var item in CollectionsMarshal.AsSpan(strings.Items))
            references.TryAdd(image.ImageBase + item.Rva, 0);

        foreach (ref readonly var item in CollectionsMarshal.AsSpan(frozen.Objects)) {
            if (item.Kind == FrozenKind.String)
                references.TryAdd(frozen.Start + (uint)item.Offset, 0);
        }

        var fieldReferences = new int[extraction.Fields.FieldTypes.Count];

        if (code is not null) {
            foreach (ref readonly var edge in CollectionsMarshal.AsSpan(code.Addresses)) {
                ref int count = ref CollectionsMarshal.GetValueRefOrNullRef(references, edge.Target);

                if (!System.Runtime.CompilerServices.Unsafe.IsNullRef(ref count))
                    ++count;
            }

            foreach (int field in CollectionsMarshal.AsSpan(code.FieldBindings))
                ++fieldReferences[field];
        }

        json.WriteStartObject();
        json.WriteString("operation", "search");
        json.WriteNumber("schema_version", 1);
        json.WriteString("input_sha256", inputSha256);
        ExtractionStatusOutput.Write(json, extraction.Stages, extraction.DictionarySignatureGaps);
        json.WriteString("map_format", extraction.Maps.Format switch {
            MapFormat.Legacy => "legacy",
            MapFormat.Metadata => "metadata",
            _ => "unknown"
        });
        JsonOutput.WriteString(json, "query", query);
        json.WriteString("comparison", "ordinal_ignore_case");
        AnalysisOutput.Write(json, extraction.UnwindAnalysis);

        json.WriteStartArray("matches");

        int hits = 0;

        char[] buffer = new char[4096];

        for (int i = 0; i < types.Length; ++i) {
            if (!names.Values[i].Contains(query, StringComparison.OrdinalIgnoreCase))
                continue;

            json.WriteStartObject();
            json.WriteString("kind", "type");
            json.WriteNumber("address", types[i].Address);
            JsonOutput.WriteString(json, "name", names.Values[i]);
            json.WriteBoolean("name_complete", names.Complete[i]);
            json.WriteEndObject();

            ++hits;
        }

        var renderer = new MethodText(extraction);

        int runtimeCount = extraction.Maps.Methods.Count + extraction.Generics.Methods.Count;
        int traceEnd = runtimeCount + extraction.Traces.Methods.Count;
        int templateEnd = traceEnd + extraction.Templates.Methods.Count;

        Span<ulong> sections = stackalloc ulong[(int)RtrSectionId.ProxyTypeMap + 1];
        sections.Clear();

        foreach (ref readonly var section in extraction.Header.Sections) {
            if ((uint)section.Id < sections.Length)
                sections[section.Id] = section.Start;
        }

        for (int i = 0; i < templateEnd; ++i) {
            ReadOnlySpan<char> text;

            int section;
            int offset;

            ulong entrypoint;
            ulong invoke = 0;
            ulong unboxed = 0;
            ulong dictionary = 0;

            bool hasSignature = true;

            if (i < runtimeCount) {
                var method = new MethodRecord(extraction, i);

                text = renderer.Render(method);
                section = method.Section;
                offset = method.Vertex;
                entrypoint = method.Entrypoint;
                invoke = method.InvokeStub;
                dictionary = method.Dictionary;
                unboxed = abi is null ? 0 : abi.Methods[i].UnboxedTarget;
            } else if (i < traceEnd) {
                ref readonly var method = ref
                    CollectionsMarshal.AsSpan(extraction.Traces.Methods)[i - runtimeCount];

                text = renderer.Render(method);
                section = (int)RtrSectionId.StackTraceMethodMapping;
                offset = method.Offset;
                entrypoint = method.Entrypoint;
                hasSignature = method.Signature != 0;
            } else {
                ref readonly var method = ref
                    CollectionsMarshal.AsSpan(extraction.Templates.Methods)[i - traceEnd];

                text = renderer.Render(method);
                section = (int)RtrSectionId.GenericMethodsTemplateMap;
                offset = method.Vertex;
                entrypoint = method.Method.Entrypoint;
            }

            var name = text[..renderer.NameLength];

            if (!name.Contains(query, StringComparison.OrdinalIgnoreCase))
                continue;

            json.WriteStartObject();
            json.WriteString("kind", "method");
            JsonOutput.WriteString(json, "name", name);

            if (hasSignature)
                JsonOutput.WriteString(json, "declared_signature", text);

            if (!renderer.SignatureComplete)
                MetadataIdentityOutput.WriteContext(json, renderer.SignatureIndex, method: true, renderer.Context);

            json.WriteNumber("section", section);
            json.WriteNumber("record", sections[section] + (uint)offset);
            json.WriteNumber("entrypoint", entrypoint);
            json.WriteNumber("invoke_stub", invoke);
            json.WriteNumber("dictionary", dictionary);

            if (abi is null && i < runtimeCount)
                json.WriteNull("unboxed_entrypoint");
            else
                json.WriteNumber("unboxed_entrypoint", unboxed);
            json.WriteEndObject();

            ++hits;
        }

        foreach (ref readonly var item in CollectionsMarshal.AsSpan(extraction.Statics.Constructors)) {
            var name = QualifiedName(
                names.Values[extraction.Types.Index[item.Type]], ".cctor", ref buffer);

            if (!name.Contains(query, StringComparison.OrdinalIgnoreCase))
                continue;

            json.WriteStartObject();
            json.WriteString("kind", "constructor");
            JsonOutput.WriteString(json, "name", name);
            json.WriteNumber("record", sections[(int)RtrSectionId.CctorContextMap] + (uint)item.Vertex);
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
            var name = QualifiedName(
                names.Values[extraction.Types.Index[item.DeclaringType]], item.Identity.Name, ref buffer);

            if (!name.Contains(query, StringComparison.OrdinalIgnoreCase))
                continue;

            json.WriteStartObject();
            json.WriteString("kind", "virtual_method");
            JsonOutput.WriteString(json, "name", name);
            json.WriteNumber("record", sections[(int)RtrSectionId.VirtualInvokeMap] + (uint)item.Vertex);
            json.WriteNumber("declaring_type", item.DeclaringType);
            json.WriteNumber("target_cell", slot.TargetCell);
            json.WriteNumber("target", slot.Target);
            json.WriteBoolean("requires_instantiating_thunk", slot.RequiresInstantiatingThunk);
            json.WriteString("status", slot.Status.ToString());
            json.WriteEndObject();

            ++hits;
        }

        SearchTypeMap(extraction.TypeMaps.External, "external_type_map", "external_type_mapping");
        SearchTypeMap(extraction.TypeMaps.Proxy, "proxy_type_map", "proxy_type_mapping");

        var marshalling = extraction.Marshalling;
        int structCount = marshalling.Structs.Count;

        for (int i = 0; i < structCount + marshalling.Delegates.Count; ++i) {
            int type;
            int offset;
            int section;

            ulong first;
            ulong second;
            ulong third;

            if (i < structCount) {
                ref readonly var item = ref CollectionsMarshal.AsSpan(marshalling.Structs)[i];

                type = item.TypeIndex;
                offset = item.Vertex;
                section = (int)RtrSectionId.StructMarshallingStubMap;
                first = item.ToNative;
                second = item.ToManaged;
                third = item.Cleanup;
            } else {
                ref readonly var item = ref CollectionsMarshal.AsSpan(marshalling.Delegates)[i - structCount];

                type = item.TypeIndex;
                offset = item.Vertex;
                section = (int)RtrSectionId.DelegateMarshallingStubMap;
                first = item.Open;
                second = item.Closed;
                third = item.Create;
            }

            var name = QualifiedName(
                i < structCount ? "native" : "delegate_marshalling", names.Values[type], ref buffer);

            if (!name.Contains(query, StringComparison.OrdinalIgnoreCase))
                continue;

            json.WriteStartObject();
            json.WriteString("kind", "marshalling");
            JsonOutput.WriteString(json, "name", name);
            json.WriteNumber("record", sections[section] + (uint)offset);
            json.WriteNumber("declaring_type", types[type].Address);
            json.WriteNumber(i < structCount ? "to_native" : "open", first);
            json.WriteNumber(i < structCount ? "to_managed" : "closed", second);
            json.WriteNumber(i < structCount ? "cleanup" : "create", third);
            json.WriteEndObject();

            ++hits;
        }

        if (code is not null) {
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
                JsonOutput.WriteString(json, "name", name);
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
            JsonOutput.WriteString(json, "name", name);
            JsonOutput.WriteString(json, "field_name", item.Name);
            json.WriteNumber("declaring_type", types[owner].Address);
            json.WriteNumber("record", sections[(int)RtrSectionId.FieldAccessMap] + (uint)item.Vertex);
            json.WriteNumber("metadata_offset", field.MetadataOffset);
            json.WriteString("location", item.Location.ToString());
            json.WriteNumber(
                item.Location == FieldLocation.Ordinal ? "ordinal" : "offset", item.Value);

            if (code is null)
                json.WriteNull("reference_count");
            else
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
            JsonOutput.WriteBase64String(json, "utf16le", data);
            json.WriteBoolean("unpaired_surrogate", item.UnpairedSurrogate);

            if (!item.UnpairedSurrogate)
                JsonOutput.WriteString(json, "text", text);

            if (code is null)
                json.WriteNull("reference_count");
            else
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
            JsonOutput.WriteString(json, "text", text);
            json.WriteString("encoding", item.Wide ? "utf-16le" : "ascii");
            json.WriteString("evidence", "nul_terminated_printable_bytes");

            if (code is null)
                json.WriteNull("reference_count");
            else
                json.WriteNumber("reference_count", references[address]);
            json.WriteEndObject();

            ++hits;
        }

        json.WriteEndArray();

        json.WriteNumber("match_count", hits);
        MetadataIdentityOutput.EndObject(json, extraction.Metadata, extraction.Signatures);

        return hits;

        void SearchTypeMap(InteropTypeMap map, string groupKind, string mappingKind) {
            foreach (ref readonly var group in map.Groups) {
                string groupName = names.Values[extraction.Types.Index[group.GroupType]];
                bool groupMatches = groupName.Contains(query, StringComparison.OrdinalIgnoreCase);
                if (groupMatches) {
                    json.WriteStartObject();
                    json.WriteString("kind", groupKind);
                    JsonOutput.WriteString(json, "name", groupName);
                    json.WriteNumber("record", map.Address + (uint)group.Vertex);
                    json.WriteNumber("group_type", group.GroupType);
                    json.WriteNumber("state", group.State);
                    json.WriteNumber("throwing_stub", group.ThrowingStub);
                    json.WriteEndObject();
                    ++hits;
                }

                foreach (ref readonly var entry in map.Entries.Slice(group.Entries.Start, group.Entries.Count)) {
                    string source = entry.Name ?? names.Values[extraction.Types.Index[entry.SourceType]];
                    string target = names.Values[extraction.Types.Index[entry.TargetType]];
                    if (!groupMatches && !source.Contains(query, StringComparison.OrdinalIgnoreCase)
                        && !target.Contains(query, StringComparison.OrdinalIgnoreCase))
                        continue;

                    json.WriteStartObject();
                    json.WriteString("kind", mappingKind);
                    JsonOutput.WriteString(json, "name", source);
                    JsonOutput.WriteString(json, "target_name", target);
                    json.WriteNumber("record", map.Address + (uint)entry.Vertex);
                    json.WriteNumber("group_record", map.Address + (uint)group.Vertex);
                    json.WriteNumber("group_type", group.GroupType);
                    json.WriteNumber("source_type", entry.SourceType);
                    json.WriteNumber("target_type", entry.TargetType);
                    json.WriteEndObject();
                    ++hits;
                }
            }
        }
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
