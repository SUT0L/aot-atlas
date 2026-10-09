using System.Collections;
using System.Reflection;
using Atlas;

internal static class OwnedCollectionChecks {
    [System.Diagnostics.CodeAnalysis.UnconditionalSuppressMessage("Trimming", "IL2026", Justification = "The API audit runs against the untrimmed test assembly.")]
    [System.Diagnostics.CodeAnalysis.UnconditionalSuppressMessage("Trimming", "IL2075", Justification = "The API audit inspects each exported result type in the untrimmed test assembly.")]
    internal static void Run() {
        foreach (var type in typeof(Extraction).Assembly.GetExportedTypes()) {
            if (type.IsAbstract)
                continue;

            foreach (var field in type.GetFields(BindingFlags.Public | BindingFlags.Instance)) {
                if (field.FieldType.IsArray
                    || typeof(IList).IsAssignableFrom(field.FieldType)
                    || typeof(IDictionary).IsAssignableFrom(field.FieldType)
                    || IsMemory(field.FieldType))
                    throw new Exception($"Writable published field: {type.Name}.{field.Name}.");
            }

            foreach (var property in type.GetProperties(BindingFlags.Public | BindingFlags.Instance)) {
                if (property.PropertyType.IsArray || IsMemory(property.PropertyType))
                    throw new Exception($"Writable published property: {type.Name}.{property.Name}.");
            }
        }

        var prototype = PeFixture.Create(new byte[64], ".rdata", 0x40000040);
        var callerFile = (byte[])prototype.FileData.Clone();
        var image = new PeImage(callerFile);
        callerFile[0] = 0;
        Assert(image.Bytes[0] == (byte)'M');

        byte[] source = [0, 2, 3, 4];
        var metadata = new Metadata(source, 7);
        var hydration = new HydratedRegion(0x1000, source, source.Length);
        source[1] = 0xFF;
        Assert(metadata.Bytes[1] == 2 && hydration.Bytes[1] == 2);

        var builder = new MethodTableBuilder();
        builder.Type(new() { Address = 0x1000, Flags = 0x00030000, GenericArity = 1 });
        var before = builder.Publish();
        var retainedTypes = before.TypeEntries;
        Assert(ReferenceEquals(before, builder.Publish()));

        ulong[] arguments = [0x1000];
        builder.Type(new() {
            Address = 0x2000,
            Flags = 0x52000000,
            BaseSize = 24,
            GenericDefinition = 0x1000
        }, arguments);
        arguments[0] = 0xDEAD;
        var after = builder.Publish();
        var retainedArguments = after.ArgumentsOf(0x2000);
        Assert(before.TypeEntries.Length == 1 && retainedTypes.Length == 1
            && retainedTypes[0].Address == 0x1000 && after.TypeEntries.Length == 2
            && retainedArguments[0] == 0x1000 && before.PointerValues.IsEmpty);

        builder.Type(new() { Address = 0x3000, Flags = 0x50000000, BaseSize = 24 });
        Assert(after.TypeEntries.Length == 2 && retainedArguments[0] == 0x1000
            && builder.Publish().TypeEntries.Length == 3);

        var copy = after.AtAddress(0x1000);
        copy.Address = 0x9999;
        Assert(after.AtAddress(0x1000).Address == 0x1000);

        var native = new MethodTableBuilder();
        native.Root(0x1000);
        bool rejected = false;

        try {
            native.Publish();
        } catch (InvalidOperationException) {
            rejected = true;
        }

        Assert(rejected);
        Console.WriteLine("Owned collections: exported classes and structs expose no mutable backing arrays, lists, dictionaries or recoverable memory; input copies, retained runtime publications and append growth passed.");
    }

    private static bool IsMemory(Type type) => type.IsGenericType
        && (type.GetGenericTypeDefinition() == typeof(ReadOnlyMemory<>)
            || type.GetGenericTypeDefinition() == typeof(Memory<>));

    private static void Assert(bool value) {
        if (!value)
            throw new Exception("Owned collection assertion failed.");
    }
}
