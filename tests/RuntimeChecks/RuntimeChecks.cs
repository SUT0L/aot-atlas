using System.Diagnostics;
using System.Runtime.CompilerServices;
using System.Security.Cryptography;
using Atlas;

#if RUNTIME_CHECKS
using Internal.Metadata.NativeFormat;
#endif

internal static class RuntimeChecks {
#if RUNTIME_CHECKS
    internal static unsafe void Run(ReadOnlySpan<string> inputs) {
        var binaries = new SortedSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (string input in inputs) {
            if (File.Exists(input)) {
                binaries.Add(Path.GetFullPath(input));
            } else if (Directory.Exists(input)) {
                foreach (string binary in Directory.EnumerateFiles(input, "*.exe", SearchOption.AllDirectories)) {
                    string? directory = Path.GetFileName(Path.GetDirectoryName(binary));
                    if (string.Equals(directory, "native", StringComparison.OrdinalIgnoreCase)
                        || string.Equals(directory, "publish", StringComparison.OrdinalIgnoreCase)) {
                        binaries.Add(Path.GetFullPath(binary));
                    }
                }
            } else {
                throw new FileNotFoundException("Runtime-source corpus input does not exist.", input);
            }
        }
        if (binaries.Count == 0)
            throw new InvalidDataException("Runtime-source corpus contains no NativeAOT executables.");

        int checkedBinaries = 0;
        int skippedBinaries = 0;
        foreach (string binary in binaries) {
            var image = new PeImage(File.ReadAllBytes(binary));
            var rtr = ReadyToRun.Read(image);
            if (!Supports(rtr.Major)) {
                ++skippedBinaries;
                continue;
            }

            int handleBits = rtr.MetadataHandleBits;
            var section = rtr.Find(313);
            var data = image.FileMemory(section.Start, checked((int)section.Length));
            var atlas = new Metadata(data, handleBits, rtr.Major < 10);
            atlas.ReadDefinitions();
            long start = Stopwatch.GetTimestamp();
            var members = new MetadataMembers(atlas);
            var enumerations = new Enumerations(atlas);
            double memberMs = Stopwatch.GetElapsedTime(start).TotalMilliseconds;
            uint Raw(Handle handle) => (uint)handle.Offset << handleBits | (uint)handle.HandleType;
            uint[] AtlasHandles(IndexRange range) => atlas.Handles.GetRange(range.Start, range.Count).ToArray();
            uint[] MemberHandles(IndexRange range) => members.Handles.GetRange(range.Start, range.Count).ToArray();

            fixed (byte* bytes = data.Span) {
                var reader = new MetadataReader((nint)bytes, data.Length);
                var namespaces = new Queue<NamespaceDefinitionHandle>();
                var types = new Queue<TypeDefinitionHandle>();
                int scopes = 0;
                foreach (var handle in reader.ScopeDefinitions) {
                    var scope = reader.GetScopeDefinition(handle);
                    Assert(atlas.Scopes.Any(entry => entry.Offset == handle.Offset
                        && entry.Name == reader.GetConstantStringValue(scope.Name).Value));
                    namespaces.Enqueue(scope.RootNamespaceDefinition);
                    ++scopes;
                }
                Assert(scopes == atlas.Scopes.Count);
                while (namespaces.Count != 0) {
                    var value = reader.GetNamespaceDefinition(namespaces.Dequeue());
                    foreach (var child in value.NamespaceDefinitions)
                        namespaces.Enqueue(child);
                    foreach (var type in value.TypeDefinitions)
                        types.Enqueue(type);
                }

                var visited = new HashSet<uint>();
                var expectedMethods = new HashSet<uint>();
                var expectedFields = new HashSet<uint>();
                var expectedProperties = new HashSet<uint>();
                var expectedEvents = new HashSet<uint>();
                var expectedGenerics = new HashSet<uint>();
                var expectedParameters = new HashSet<uint>();
                while (types.Count != 0) {
                    var type = reader.GetTypeDefinition(types.Dequeue());
                    Assert(visited.Add((uint)type.Handle.Offset));
                    var actual = atlas.Types[atlas.TypeIndex[(uint)type.Handle.Offset]];
                    Assert(actual.Flags == (uint)type.Flags && actual.Size == type.Size && actual.Packing == type.PackingSize);
                    uint expectedBase = Raw(type.BaseType);
                    if (actual.BaseType != expectedBase || actual.EnclosingType != type.EnclosingType.Offset) {
                        throw new InvalidDataException($"{binary}: type 0x{type.Handle.Offset:X} has base/enclosing "
                            + $"0x{actual.BaseType:X}/0x{actual.EnclosingType:X}; Microsoft NativeFormatReader reports "
                            + $"0x{expectedBase:X}/0x{type.EnclosingType.Offset:X}.");
                    }
                    Assert(AtlasHandles(actual.Methods).SequenceEqual(((MethodHandle[])[.. type.Methods]).Select(handle => (uint)handle.Offset)));
                    Assert(AtlasHandles(actual.Fields).SequenceEqual(((FieldHandle[])[.. type.Fields]).Select(handle => (uint)handle.Offset)));
                    Assert(AtlasHandles(actual.Properties).SequenceEqual(((PropertyHandle[])[.. type.Properties]).Select(handle => (uint)handle.Offset)));
                    Assert(AtlasHandles(actual.Events).SequenceEqual(((EventHandle[])[.. type.Events]).Select(handle => (uint)handle.Offset)));
                    Assert(AtlasHandles(actual.GenericParameters).SequenceEqual(((GenericParameterHandle[])[.. type.GenericParameters]).Select(handle => (uint)handle.Offset)));
                    foreach (var nested in type.NestedTypes)
                        types.Enqueue(nested);
                    foreach (var handle in type.Methods)
                        expectedMethods.Add((uint)handle.Offset);
                    foreach (var handle in type.Fields)
                        expectedFields.Add((uint)handle.Offset);
                    foreach (var handle in type.Properties)
                        expectedProperties.Add((uint)handle.Offset);
                    foreach (var handle in type.Events)
                        expectedEvents.Add((uint)handle.Offset);
                    foreach (var handle in type.GenericParameters)
                        expectedGenerics.Add((uint)handle.Offset);
                }
                Assert(visited.SetEquals(atlas.TypeIndex.Keys));
                Assert(expectedMethods.SetEquals(atlas.MethodIndex.Keys));
                Assert(expectedFields.SetEquals(atlas.FieldIndex.Keys));
                Assert(expectedProperties.SetEquals(members.Properties.Keys) && expectedEvents.SetEquals(members.Events.Keys));

                foreach (uint offset in expectedMethods) {
                    var reference = reader.GetMethod(new MethodHandle((int)offset));
                    var actual = atlas.Methods[atlas.MethodIndex[offset]];
                    Assert(actual.Name == reader.GetConstantStringValue(reference.Name).Value && actual.Flags == (uint)reference.Flags);
                    Assert(actual.ImplementationFlags == (uint)reference.ImplFlags && actual.SignatureOffset == reference.Signature.Offset);
                    Assert(AtlasHandles(actual.Parameters).SequenceEqual(((ParameterHandle[])[.. reference.Parameters]).Select(handle => (uint)handle.Offset)));
                    Assert(AtlasHandles(actual.GenericParameters).SequenceEqual(((GenericParameterHandle[])[.. reference.GenericParameters]).Select(handle => (uint)handle.Offset)));
                    foreach (var handle in reference.Parameters)
                        expectedParameters.Add((uint)handle.Offset);
                    foreach (var handle in reference.GenericParameters)
                        expectedGenerics.Add((uint)handle.Offset);
                }
                foreach (uint offset in expectedFields) {
                    var reference = reader.GetField(new FieldHandle((int)offset));
                    var signature = reader.GetFieldSignature(reference.Signature);
                    var actual = atlas.Fields[atlas.FieldIndex[offset]];
                    Assert(actual.Name == reader.GetConstantStringValue(reference.Name).Value && actual.Flags == (uint)reference.Flags);
                    Assert(actual.SignatureOffset == reference.Signature.Offset && actual.Signature == atlas.TypeSignature(Raw(signature.Type)));
                    Assert(actual.DefaultValue == Raw(reference.DefaultValue) && actual.ExplicitOffset == reference.Offset);
                    Assert(AtlasHandles(actual.Attributes).SequenceEqual(((CustomAttributeHandle[])[.. reference.CustomAttributes]).Select(handle => (uint)handle.Offset)));
                }
                Assert(expectedParameters.SetEquals(members.Parameters.Keys) && expectedGenerics.SetEquals(members.GenericParameters.Keys));
                foreach (uint offset in expectedParameters) {
                    var reference = reader.GetParameter(new ParameterHandle((int)offset));
                    var actual = members.Parameters[offset];
                    Assert(actual.Name == reader.GetConstantStringValue(reference.Name).Value && actual.Flags == (uint)reference.Flags);
                    Assert(actual.Sequence == reference.Sequence && actual.DefaultValue == Raw(reference.DefaultValue));
                    Assert(MemberHandles(actual.Attributes).SequenceEqual(((CustomAttributeHandle[])[.. reference.CustomAttributes]).Select(handle => (uint)handle.Offset)));
                }
                foreach (uint offset in expectedGenerics) {
                    var reference = reader.GetGenericParameter(new GenericParameterHandle((int)offset));
                    var actual = members.GenericParameters[offset];
                    Assert(actual.Name == reader.GetConstantStringValue(reference.Name).Value && actual.Flags == (uint)reference.Flags);
                    Assert(actual.Number == reference.Number && actual.Kind == (uint)reference.Kind);
                    Assert(MemberHandles(actual.Constraints).SequenceEqual(((Handle[])[.. reference.Constraints]).Select(Raw)));
                    Assert(MemberHandles(actual.Attributes).SequenceEqual(((CustomAttributeHandle[])[.. reference.CustomAttributes]).Select(handle => (uint)handle.Offset)));
                }
                foreach (uint offset in expectedProperties) {
                    var reference = reader.GetProperty(new PropertyHandle((int)offset));
                    var signature = reader.GetPropertySignature(reference.Signature);
                    var actual = members.Properties[offset];
                    Assert(actual.Name == reader.GetConstantStringValue(reference.Name).Value && actual.Flags == (uint)reference.Flags);
                    Assert(actual.DefaultValue == Raw(reference.DefaultValue) && actual.SignatureOffset == reference.Signature.Offset);
                    Assert(actual.CallingConvention == (uint)signature.CallingConvention && actual.Type == atlas.TypeSignature(Raw(signature.Type)));
                    Assert(MemberHandles(actual.Parameters).SequenceEqual(((Handle[])[.. signature.Parameters]).Select(Raw)));
                    Assert(MemberHandles(actual.Attributes).SequenceEqual(((CustomAttributeHandle[])[.. reference.CustomAttributes]).Select(handle => (uint)handle.Offset)));
                    Assert(members.Accessors.GetRange(actual.Accessors.Start, actual.Accessors.Count).Select(entry => entry.Offset)
                        .SequenceEqual(((MethodSemanticsHandle[])[.. reference.MethodSemantics]).Select(handle => (uint)handle.Offset)));
                }
                foreach (uint offset in expectedEvents) {
                    var reference = reader.GetEvent(new EventHandle((int)offset));
                    var actual = members.Events[offset];
                    Assert(actual.Name == reader.GetConstantStringValue(reference.Name).Value && actual.Flags == (uint)reference.Flags);
                    Assert(actual.Type == atlas.TypeSignature(Raw(reference.Type)));
                    Assert(MemberHandles(actual.Attributes).SequenceEqual(((CustomAttributeHandle[])[.. reference.CustomAttributes]).Select(handle => (uint)handle.Offset)));
                    Assert(members.Accessors.GetRange(actual.Accessors.Start, actual.Accessors.Count).Select(entry => entry.Offset)
                        .SequenceEqual(((MethodSemanticsHandle[])[.. reference.MethodSemantics]).Select(handle => (uint)handle.Offset)));
                }
                foreach (var actual in members.Accessors) {
                    var reference = reader.GetMethodSemantics(new MethodSemanticsHandle((int)actual.Offset));
                    Assert(actual.Semantics == (uint)reference.Attributes && actual.Method == reference.Method.Offset);
                    Assert(atlas.MethodIndex.ContainsKey(actual.Method));
                }

                int enumMembers = 0;
                foreach (var definition in enumerations.Definitions) {
                    for (int i = definition.Members.Start; i < definition.Members.End; ++i) {
                        var member = enumerations.Members[i];
                        var field = atlas.Fields[member.Field];
                        var reference = reader.GetField(new FieldHandle((int)field.Offset));
                        var expected = IntegerConstant(reader, reference.DefaultValue);
                        Assert(member.Bits == expected.Bits && definition.Width == expected.Width && definition.Signed == expected.Signed);
                        ++enumMembers;
                    }
                }

                Console.WriteLine($"RTR {rtr.Major}.{rtr.Minor} {Path.GetRelativePath(Environment.CurrentDirectory, binary)}: "
                    + $"Microsoft runtime source matches {visited.Count} types, {expectedMethods.Count} methods, {expectedFields.Count} fields, "
                    + $"{expectedProperties.Count} properties, {expectedEvents.Count} events, {expectedParameters.Count} parameters, "
                    + $"{expectedGenerics.Count} generic parameters, {enumMembers} enum constants; member decode {memberMs:F3} ms; "
                    + $"sha256={Convert.ToHexStringLower(SHA256.HashData(image.FileData))}");
            }
            ++checkedBinaries;
        }
        if (checkedBinaries == 0)
            throw new InvalidDataException("Runtime-source corpus contains no executables for this Microsoft metadata schema.");
        Console.WriteLine($"Runtime checks: {checkedBinaries} executables matched Microsoft NativeFormatReader; "
            + $"{skippedBinaries} used another metadata schema.");
    }

    private static bool Supports(ushort major) {
#if READER_NET8
        return major < 10;
#elif READER_NET9
        return major is >= 10 and < 12;
#else
        return major >= 12;
#endif
    }

    private static (ulong Bits, byte Width, bool Signed) IntegerConstant(MetadataReader reader, Handle handle) {
        return handle.HandleType switch {
            HandleType.ConstantSByteValue => (unchecked((byte)reader.GetConstantSByteValue(new ConstantSByteValueHandle(handle)).Value), 1, true),
            HandleType.ConstantByteValue => (reader.GetConstantByteValue(new ConstantByteValueHandle(handle)).Value, 1, false),
            HandleType.ConstantInt16Value => (unchecked((ushort)reader.GetConstantInt16Value(new ConstantInt16ValueHandle(handle)).Value), 2, true),
            HandleType.ConstantUInt16Value => (reader.GetConstantUInt16Value(new ConstantUInt16ValueHandle(handle)).Value, 2, false),
            HandleType.ConstantInt32Value => (unchecked((uint)reader.GetConstantInt32Value(new ConstantInt32ValueHandle(handle)).Value), 4, true),
            HandleType.ConstantUInt32Value => (reader.GetConstantUInt32Value(new ConstantUInt32ValueHandle(handle)).Value, 4, false),
            HandleType.ConstantInt64Value => (unchecked((ulong)reader.GetConstantInt64Value(new ConstantInt64ValueHandle(handle)).Value), 8, true),
            HandleType.ConstantUInt64Value => (reader.GetConstantUInt64Value(new ConstantUInt64ValueHandle(handle)).Value, 8, false),
            _ => throw new InvalidDataException($"Microsoft runtime source reports non-integral enum constant {handle.HandleType}.")
        };
    }

    private static void Assert(bool condition, [CallerArgumentExpression(nameof(condition))] string expression = "") {
        if (!condition)
            throw new InvalidDataException("Atlas disagrees with Microsoft NativeFormatReader: " + expression);
    }
#else
    internal static void Run(ReadOnlySpan<string> inputs) {
        throw new InvalidOperationException("Run the RuntimeChecks MSBuild target with a dotnet/runtime checkout.");
    }
#endif
}
