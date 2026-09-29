using System.Diagnostics;
using System.Text.Json;
using Atlas;

internal static class ExtractCommand {
    internal static void Write(Utf8JsonWriter json, string inputSha256, PeImage image, ReadyToRun rtr, MapFormat format) {
        json.WriteStartObject();
        json.WriteString("operation", "extract");
        json.WriteNumber("schema_version", 1);
        json.WriteString("input_sha256", inputSha256);

        var section = rtr.Find(313);
        var metadata = new Metadata(section.Length == 0 ? default : image.FileMemory(section.Start, checked((int)section.Length)),
            rtr.MetadataHandleBits, rtr.Major < 10);
        long start = Stopwatch.GetTimestamp();
        metadata.ReadDefinitions();
        var members = new MetadataMembers(metadata);
        double metadataSeconds = Stopwatch.GetElapsedTime(start).TotalSeconds;
        json.WritePropertyName("metadata");
        MetadataOutput.Write(json, inputSha256, metadata, members, image, rtr, metadataSeconds);

        start = Stopwatch.GetTimestamp();
        var fixups = RuntimeTables.Fixups(image, rtr.Find(308));
        var maps = new ReflectionMaps();
        maps.Read(image, rtr, metadata, fixups, format);
        double mapsSeconds = Stopwatch.GetElapsedTime(start).TotalSeconds;
        json.WritePropertyName("maps");
        MapsOutput.Write(json, inputSha256, maps, image, metadata, mapsSeconds);

        var extraction = new Extraction(image, rtr, metadata, maps, fixups);
        json.WritePropertyName("dictionaries");
        DictionariesOutput.Write(json, inputSha256, extraction);
        json.WritePropertyName("inspect");
        InspectOutput.Write(json, inputSha256, extraction);
        json.WritePropertyName("types");
        TypesOutput.Write(json, inputSha256, extraction.Types, extraction.Gc, extraction.Names, image, extraction.TypesSeconds);
        json.WritePropertyName("fields");
        FieldsOutput.Write(json, inputSha256, extraction);
        json.WritePropertyName("dispatch");
        DispatchOutput.Write(json, inputSha256, image, extraction.Types, extraction.Names, extraction.Dispatch,
            extraction.Virtuals, extraction.DispatchSeconds);
        json.WritePropertyName("statics");
        StaticsOutput.Write(json, inputSha256, extraction);
        json.WritePropertyName("frozen");
        FrozenOutput.Write(json, inputSha256, extraction);
        json.WritePropertyName("enums");
        EnumsOutput.Write(json, inputSha256, extraction);
        json.WritePropertyName("gvm");
        GvmOutput.Write(json, inputSha256, extraction);
        json.WritePropertyName("marshalling");
        MarshallingOutput.Write(json, inputSha256, extraction);
        json.WritePropertyName("pinvoke");
        PInvokeOutput.Write(json, inputSha256, extraction);
        json.WritePropertyName("resources");
        ResourcesOutput.Write(json, inputSha256, image, extraction.Resources, null);
        json.WritePropertyName("linkage");
        LinkageOutput.Write(json, inputSha256, image, extraction.Linkage);
        json.WritePropertyName("unwind");
        UnwindOutput.Write(json, inputSha256, image, extraction.Unwind);
        json.WritePropertyName("exceptions");
        ExceptionsOutput.Write(json, inputSha256, image, extraction.Unwind, extraction.Managed);

        long allocated = GC.GetAllocatedBytesForCurrentThread();
        start = Stopwatch.GetTimestamp();
        var abi = new ManagedAbi(extraction);
        double abiSeconds = Stopwatch.GetElapsedTime(start).TotalSeconds;
        var code = new CodeFlow(extraction, abi);
        double codeSeconds = Stopwatch.GetElapsedTime(start).TotalSeconds;
        allocated = GC.GetAllocatedBytesForCurrentThread() - allocated;
        json.WritePropertyName("code");
        CodeOutput.Write(json, inputSha256, extraction, code, codeSeconds, allocated);
        start = Stopwatch.GetTimestamp();
        var dispatchCells = new DispatchCells(extraction, code);
        json.WritePropertyName("dispatch_cells");
        DispatchCellsOutput.Write(json, inputSha256, extraction, dispatchCells, Stopwatch.GetElapsedTime(start).TotalSeconds);
        json.WritePropertyName("runtime_helpers");
        RuntimeHelpersOutput.Write(json, inputSha256, new RuntimeHelpers(extraction, code));
        json.WritePropertyName("methods");
        MethodsOutput.Write(json, inputSha256, extraction, abi, abiSeconds);
        json.WritePropertyName("properties");
        PropertyOutput.Write(json, inputSha256, extraction, new PropertyProjections(extraction, abi));

        allocated = GC.GetAllocatedBytesForCurrentThread();
        start = Stopwatch.GetTimestamp();
        var strings = new NativeStrings(image, rtr.Sections);
        double stringSeconds = Stopwatch.GetElapsedTime(start).TotalSeconds;
        allocated = GC.GetAllocatedBytesForCurrentThread() - allocated;
        json.WritePropertyName("strings");
        StringsOutput.Write(json, inputSha256, image, strings, stringSeconds, allocated);
        json.WritePropertyName("sections");
        SectionsOutput.Write(json, inputSha256, image, rtr);
        json.WriteEndObject();
    }
}
