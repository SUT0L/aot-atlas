using System.Diagnostics;
using System.Globalization;
using System.Text.Json;

#if RUNTIME_CHECKS
using Internal.Metadata.NativeFormat;

internal static class CliMetadataChecks {
    internal static void Run(string cli, string binary, string inputSha256, MetadataReader reader, int handleBits,
        HashSet<uint> types, HashSet<uint> methods, HashSet<uint> fields,
        HashSet<uint> properties, HashSet<uint> events, HashSet<uint> parameters, HashSet<uint> generics) {
        using var document = Read(cli, binary);
        var root = document.RootElement;
        int records = 0;
        int values = 0;
        int sequences = 0;

        void Require(bool condition, string location) {
            if (!condition)
                throw new InvalidDataException($"{binary}: CLI metadata disagrees with Microsoft NativeFormatReader at {location}.");
        }

        Require(root.GetProperty("operation").GetString() == "metadata"
            && root.GetProperty("schema_version").GetInt32() == 1
            && root.GetProperty("input_sha256").GetString() == inputSha256, "input identity and schema");

        void Universe(string collection, HashSet<uint> expected) {
            var offsets = new HashSet<uint>();
            foreach (var property in root.GetProperty(collection).EnumerateObject()) {
                Require(uint.TryParse(property.Name, NumberStyles.None, CultureInfo.InvariantCulture, out uint offset)
                    && offsets.Add(offset), collection + " record keys");
            }
            Require(offsets.SetEquals(expected), collection + " complete record set");
            records += offsets.Count;
        }

        JsonElement Record(string collection, uint offset) => root.GetProperty(collection)
            .GetProperty(offset.ToString(CultureInfo.InvariantCulture));

        void Number(JsonElement record, string field, uint expected) {
            Require(record.GetProperty(field).GetUInt32() == expected, field);
            ++values;
        }

        void Name(JsonElement record, string field, string? expected) {
            Require(record.GetProperty(field).GetString() == (expected ?? ""), field);
            ++values;
        }

        void Sequence(JsonElement record, string field, IEnumerable<uint> expected, string? member = null) {
            var actual = record.GetProperty(field).EnumerateArray()
                .Select(value => member is null ? value.GetUInt32() : value.GetProperty(member).GetUInt32());
            Require(actual.SequenceEqual(expected), field + " ordered handles");
            ++sequences;
        }

        uint Raw(Handle handle) => (uint)handle.Offset << handleBits | (uint)handle.HandleType;

        void Accessors(JsonElement record, MethodSemanticsHandleCollection expected) {
            var actual = record.GetProperty("accessors");
            MethodSemanticsHandle[] handles = [.. expected];
            Require(actual.GetArrayLength() == handles.Length, "accessors count");
            for (int i = 0; i < handles.Length; ++i) {
                var source = reader.GetMethodSemantics(handles[i]);
                var entry = actual[i];
                Number(entry, "offset", (uint)handles[i].Offset);
                Number(entry, "semantics", (uint)source.Attributes);
                Number(entry, "method", (uint)source.Method.Offset);
            }
            ++sequences;
        }

        Universe("types", types);
        Universe("methods", methods);
        Universe("fields", fields);
        Universe("properties", properties);
        Universe("events", events);
        Universe("parameters", parameters);
        Universe("generic_parameters", generics);

        var scopes = root.GetProperty("scopes");
        int scopeIndex = 0;
        foreach (var handle in reader.ScopeDefinitions) {
            var source = reader.GetScopeDefinition(handle);
            Require(scopeIndex < scopes.GetArrayLength()
                && scopes[scopeIndex][0].GetUInt32() == handle.Offset
                && scopes[scopeIndex][1].GetString() == reader.GetConstantStringValue(source.Name).Value,
                "scopes ordered offsets and names");
            ++scopeIndex;
            values += 2;
        }
        Require(scopeIndex == scopes.GetArrayLength(), "scopes complete record set");
        records += scopeIndex;

        var namespaces = new Dictionary<uint, (string Name, uint Scope)>();
        var identities = new Dictionary<uint, (string Name, uint Scope)>();

        (string Name, uint Scope) NamespaceIdentity(uint offset) {
            if (offset == 0)
                return ("", 0);
            if (namespaces.TryGetValue(offset, out var known))
                return known;
            var source = reader.GetNamespaceDefinition(new NamespaceDefinitionHandle((int)offset));
            string name = reader.GetConstantStringValue(source.Name).Value ?? "";
            var parent = source.ParentScopeOrNamespace;
            var prefix = parent.HandleType == HandleType.ScopeDefinition
                ? (Name: "", Scope: (uint)parent.Offset)
                : NamespaceIdentity((uint)parent.Offset);
            var result = (prefix.Name.Length == 0 ? name : name.Length == 0 ? prefix.Name : prefix.Name + "." + name,
                prefix.Scope);
            namespaces.Add(offset, result);
            return result;
        }

        (string Name, uint Scope) TypeIdentity(uint offset) {
            if (identities.TryGetValue(offset, out var known))
                return known;
            var source = reader.GetTypeDefinition(new TypeDefinitionHandle((int)offset));
            string name = reader.GetConstantStringValue(source.Name).Value ?? "";
            bool nested = source.EnclosingType.Offset != 0;
            var prefix = nested ? TypeIdentity((uint)source.EnclosingType.Offset)
                : NamespaceIdentity((uint)source.NamespaceDefinition.Offset);
            var result = (prefix.Name.Length == 0 ? name : prefix.Name + (nested ? "+" : ".") + name, prefix.Scope);
            identities.Add(offset, result);
            return result;
        }

        foreach (uint offset in types)
            TypeIdentity(offset);
        var collisions = identities.Values.GroupBy(value => value.Name, StringComparer.Ordinal)
            .Where(group => group.Select(value => value.Scope).Distinct().Skip(1).Any())
            .Select(group => group.Key).ToHashSet(StringComparer.Ordinal);
        var methodOwners = new Dictionary<uint, HashSet<uint>>();

        foreach (uint offset in types) {
            var source = reader.GetTypeDefinition(new TypeDefinitionHandle((int)offset));
            var actual = Record("types", offset);
            var identity = identities[offset];
            string name = identity.Name;
            if (collisions.Contains(name)) {
                var scope = reader.GetScopeDefinition(new ScopeDefinitionHandle((int)identity.Scope));
                name = $"[{reader.GetConstantStringValue(scope.Name).Value}@scope_{identity.Scope:X}]{name}";
            }
            Name(actual, "name", name);
            Number(actual, "scope", identity.Scope);
            Number(actual, "flags", (uint)source.Flags);
            Number(actual, "base_type", Raw(source.BaseType));
            Number(actual, "enclosing_type", (uint)source.EnclosingType.Offset);
            Number(actual, "size", source.Size);
            Number(actual, "packing", source.PackingSize);
            Sequence(actual, "interfaces", ((Handle[])[.. source.Interfaces]).Select(Raw), member: "handle");
            Sequence(actual, "methods", ((MethodHandle[])[.. source.Methods]).Select(handle => (uint)handle.Offset));
            Sequence(actual, "fields", ((FieldHandle[])[.. source.Fields]).Select(handle => (uint)handle.Offset));
            Sequence(actual, "properties", ((PropertyHandle[])[.. source.Properties]).Select(handle => (uint)handle.Offset));
            Sequence(actual, "events", ((EventHandle[])[.. source.Events]).Select(handle => (uint)handle.Offset));
            Sequence(actual, "generic_parameters", ((GenericParameterHandle[])[.. source.GenericParameters])
                .Select(handle => (uint)handle.Offset));

            foreach (var handle in source.Methods) {
                uint method = (uint)handle.Offset;
                if (!methodOwners.TryGetValue(method, out var owners)) {
                    owners = new HashSet<uint>();
                    methodOwners.Add(method, owners);
                }
                owners.Add(offset);
            }
        }

        foreach (uint offset in methods) {
            var source = reader.GetMethod(new MethodHandle((int)offset));
            var actual = Record("methods", offset);
            Name(actual, "name", reader.GetConstantStringValue(source.Name).Value);
            Number(actual, "flags", (uint)source.Flags);
            Number(actual, "implementation_flags", (uint)source.ImplFlags);
            Number(actual, "signature_offset", (uint)source.Signature.Offset);
            var owners = methodOwners[offset];
            Number(actual, "unique_owner", owners.Count == 1 ? owners.Single() : 0);
            Sequence(actual, "parameters", ((ParameterHandle[])[.. source.Parameters]).Select(handle => (uint)handle.Offset));
            Sequence(actual, "generic_parameters", ((GenericParameterHandle[])[.. source.GenericParameters])
                .Select(handle => (uint)handle.Offset));
        }

        foreach (uint offset in fields) {
            var source = reader.GetField(new FieldHandle((int)offset));
            var actual = Record("fields", offset);
            Name(actual, "name", reader.GetConstantStringValue(source.Name).Value);
            Number(actual, "flags", (uint)source.Flags);
            Number(actual, "signature_offset", (uint)source.Signature.Offset);
            Number(actual, "default_value", Raw(source.DefaultValue));
            Number(actual, "explicit_offset", source.Offset);
        }

        foreach (uint offset in properties) {
            var source = reader.GetProperty(new PropertyHandle((int)offset));
            var signature = reader.GetPropertySignature(source.Signature);
            var actual = Record("properties", offset);
            Name(actual, "name", reader.GetConstantStringValue(source.Name).Value);
            Number(actual, "flags", (uint)source.Flags);
            Number(actual, "signature_offset", (uint)source.Signature.Offset);
            Number(actual, "default_value", Raw(source.DefaultValue));
            Number(actual, "calling_convention", (uint)signature.CallingConvention);
            Sequence(actual, "attributes", ((CustomAttributeHandle[])[.. source.CustomAttributes])
                .Select(handle => (uint)handle.Offset));
            Accessors(actual, source.MethodSemantics);
        }

        foreach (uint offset in events) {
            var source = reader.GetEvent(new EventHandle((int)offset));
            var actual = Record("events", offset);
            Name(actual, "name", reader.GetConstantStringValue(source.Name).Value);
            Number(actual, "flags", (uint)source.Flags);
            Sequence(actual, "attributes", ((CustomAttributeHandle[])[.. source.CustomAttributes])
                .Select(handle => (uint)handle.Offset));
            Accessors(actual, source.MethodSemantics);
        }

        foreach (uint offset in parameters) {
            var source = reader.GetParameter(new ParameterHandle((int)offset));
            var actual = Record("parameters", offset);
            Name(actual, "name", reader.GetConstantStringValue(source.Name).Value);
            Number(actual, "flags", (uint)source.Flags);
            Number(actual, "sequence", source.Sequence);
            Number(actual, "default_value", Raw(source.DefaultValue));
            Sequence(actual, "attributes", ((CustomAttributeHandle[])[.. source.CustomAttributes])
                .Select(handle => (uint)handle.Offset));
        }

        foreach (uint offset in generics) {
            var source = reader.GetGenericParameter(new GenericParameterHandle((int)offset));
            var actual = Record("generic_parameters", offset);
            Name(actual, "name", reader.GetConstantStringValue(source.Name).Value);
            Number(actual, "flags", (uint)source.Flags);
            Number(actual, "number", source.Number);
            Name(actual, "kind", (uint)source.Kind == 0 ? "type" : "method");
            Sequence(actual, "attributes", ((CustomAttributeHandle[])[.. source.CustomAttributes])
                .Select(handle => (uint)handle.Offset));
        }

        Require(records > 0 && values > 0 && sequences > 0, "nonzero record, value and ordered-handle comparisons");
        Console.WriteLine($"CLI metadata: {records} independently enumerated records, {values} values and "
            + $"{sequences} ordered handle collections matched Microsoft NativeFormatReader.");
    }

    private static JsonDocument Read(string cli, string binary) {
        string output = Path.Combine(Path.GetTempPath(), "atlas-runtime-metadata-" + Guid.NewGuid().ToString("N") + ".json");
        try {
            var start = new ProcessStartInfo {
                FileName = cli.EndsWith(".dll", StringComparison.OrdinalIgnoreCase) ? "dotnet" : cli,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                UseShellExecute = false
            };
            if (cli.EndsWith(".dll", StringComparison.OrdinalIgnoreCase))
                start.ArgumentList.Add(cli);
            start.ArgumentList.Add("metadata");
            start.ArgumentList.Add(binary);
            start.ArgumentList.Add(output);
            using var process = Process.Start(start) ?? throw new InvalidOperationException("Could not start Atlas CLI.");
            var stdout = process.StandardOutput.ReadToEndAsync();
            var stderr = process.StandardError.ReadToEndAsync();
            if (!process.WaitForExit(60_000)) {
                process.Kill(entireProcessTree: true);
                throw new TimeoutException($"Atlas CLI metadata exceeded 60 seconds for {binary}.");
            }
            string error = stderr.GetAwaiter().GetResult();
            string log = stdout.GetAwaiter().GetResult();
            if (process.ExitCode != 0)
                throw new InvalidDataException($"Atlas CLI metadata failed for {binary} with exit {process.ExitCode}: {error}{log}");
            return JsonDocument.Parse(File.ReadAllBytes(output));
        } finally {
            File.Delete(output);
        }
    }
}
#endif
