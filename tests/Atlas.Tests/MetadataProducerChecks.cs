using Atlas;

internal static class MetadataProducerChecks {
    internal static void Run(ReadOnlySpan<string> binaries) {
        if (binaries.IsEmpty)
            throw new ArgumentException("Expected at least one compiled metadata producer.");

        foreach (string binary in binaries) {
            var metadata = Read(binary);
            CheckRichArguments(metadata);
            CheckTypeSpecifications(metadata);
            CheckDefaults(metadata);
        }

        Console.WriteLine($"Compiler metadata producers: {binaries.Length} artifacts each matched ten typed attribute arguments, six typeof shapes and source-declared field/parameter defaults.");
    }

    private static MetadataBuilder Read(string path) {
        var image = PeImage.ReadFile(path);
        var metadata = MetadataBuilder.FromImage(image, ReadyToRun.Read(image));
        metadata.ReadDefinitions();

        return metadata;
    }

    private static void CheckRichArguments(MetadataBuilder metadata) {
        var packet = metadata.Types.Single(type => type.Name == "Packet");
        var attribute = Enumerable.Range(packet.Attributes.Start, packet.Attributes.Count)
            .Select(index => metadata.AttributePayload(metadata.Handles[index]))
            .Single(payload => payload.Type == "RichAttribute");
        var arguments = attribute.FixedArgumentValues.ToArray();

        Assert(arguments.Length == 10, "Rich attribute lost a source-declared argument.");

        string[] kinds = [
            "array", "array", "type", "uint32", "byte", "char", "double", "int64", "uint64", "array"
        ];

        Assert(arguments.Select(value => value.Kind).SequenceEqual(kinds),
            "Attribute payload kind labels disagree with the source-declared value types.");
        Assert(arguments[0].Type == "int32[]" && arguments[1].Type == "string[]"
            && arguments[9].Type == "object[]", "Attribute array element labels changed.");

        Assert(arguments[0].Value is System.Collections.ObjectModel.ReadOnlyCollection<int> integers
            && integers.SequenceEqual(new[] { -1, 7, 123456 }), "Int32 array values changed.");
        Assert(arguments[1].Value is System.Collections.ObjectModel.ReadOnlyCollection<MetadataValue> names && names.Count == 2
            && names[0].Kind == "string" && names[0].Value is "alpha"
            && names[1].Kind == "null" && names[1].Value is null, "String/null array values changed.");
        Assert(arguments[2].Kind == "type" && arguments[2].Value is "Packet", "typeof(Packet) changed.");
        Assert(arguments[3].Value is uint mode && mode == 0xFEDCBA98, "Unsigned enum payload changed.");
        Assert(arguments[4].Value is byte number && number == 255, "Byte argument changed.");
        Assert(arguments[5].Value is ushort character && character == 'Ω', "Char argument changed.");
        Assert(arguments[6].Value is double fraction && fraction == 3.25, "Double argument changed.");
        Assert(arguments[7].Value is long signed && signed == long.MinValue, "Signed Int64 boundary changed.");
        Assert(arguments[8].Value is ulong unsigned && unsigned == ulong.MaxValue, "Unsigned Int64 boundary changed.");
        Assert(arguments[9].Value is System.Collections.ObjectModel.ReadOnlyCollection<MetadataValue> mixed && mixed.Count == 3
            && mixed[0].Value is false
            && mixed[1].Value is short negative && negative == -2
            && mixed[2].Value is float single && single == 1.5f, "Mixed boxed argument types/values changed.");
    }

    private static void CheckTypeSpecifications(MetadataBuilder metadata) {
        var contract = metadata.Types.Single(type => type.Name == "Contract");
        var attribute = Enumerable.Range(contract.Attributes.Start, contract.Attributes.Count)
            .Select(index => metadata.AttributePayload(metadata.Handles[index]))
            .Single(payload => payload.Type == "TypesAttribute");

        Assert(attribute.FixedArguments.Length == 2 && attribute.NamedArguments.Length == 1,
            "Type-specification producer lost a declared argument.");
        Assert(attribute.FixedArguments[0].Kind == "type"
            && attribute.FixedArguments[0].Value is "System.Int32[]", "Vector typeof value changed.");

        string[] expected = [
            "System.Collections.Generic.Dictionary`2<System.String,System.Int32>",
            "System.Int32[,]",
            "System.Int32*",
            "Outer`1+Inner`1<System.Int32,System.String>"
        ];
        var values = attribute.FixedArgumentValues[1].Value as System.Collections.ObjectModel.ReadOnlyCollection<MetadataValue>;

        Assert(values is not null && values.All(value => value.Kind == "type")
            && values.Select(value => value.Value).SequenceEqual(expected),
            "Closed generic, multidimensional, pointer or nested typeof values changed.");
        Assert(attribute.NamedArguments[0].Name == "Named"
            && attribute.NamedArguments[0].Flags == 0
            && attribute.NamedArguments[0].Type == "System.Type"
            && attribute.NamedArguments[0].Value.Kind == "type"
            && attribute.NamedArguments[0].Value.Value is "System.Collections.Generic.List`1<System.Int32[]>",
            "Named typeof value changed.");
    }

    private static void CheckDefaults(MetadataBuilder metadata) {
        var field = metadata.Fields.Single(value => value.Name == "WireId");
        var members = metadata.MembersBuilder;
        members.ReadAll(default);
        var parameter = members.Parameters.Values.Single(value => value.Name == "count");

        Assert(metadata.Constant(field.DefaultValue).Value is int wireId && wireId == 0x1234,
            "Source-declared field constant changed.");
        Assert(metadata.Constant(parameter.DefaultValue).Value is int count && count == 7,
            "Source-declared optional parameter default changed.");
    }

    private static void Assert(bool condition, string error) {
        if (!condition)
            throw new Exception(error);
    }
}
