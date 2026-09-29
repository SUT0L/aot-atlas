using System.Diagnostics;
using System.Security.Cryptography;
using System.Text.Json;
using Atlas;

MapFormat requestedFormat = MapFormat.Auto;
string command = args.Length == 0 ? "" : args[0];
bool search = command == "search";
bool resolveDispatch = command == "resolve-dispatch";
bool needsExtraction = command is "search" or "header" or "types" or "methods" or "dispatch" or "statics" or "fields"
    or "frozen" or "enums" or "gvm" or "marshalling" or "pinvoke" or "code" or "dictionaries" or "runtime-helpers" or "properties"
    or "dispatch-cells" or "resolve-dispatch";
bool needsMaps = needsExtraction || command == "maps";
bool needsMetadata = needsMaps || command == "metadata";
bool knownCommand = needsMetadata || command is "extract" or "inspect" or "sections" or "strings"
    or "resources" or "linkage" or "unwind" or "exceptions";

int positionalCount = resolveDispatch ? 6 : search ? 4 : 3;
bool validArguments = args.Length == positionalCount;
if (args.Length == positionalCount + 2 && (needsMaps || command == "extract") && args[positionalCount] == "--map-format") {
    requestedFormat = args[positionalCount + 1] switch {
        "legacy" => MapFormat.Legacy,
        "metadata" => MapFormat.Metadata,
        _ => MapFormat.Auto
    };
    validArguments = requestedFormat != MapFormat.Auto;
}

if (!validArguments || !knownCommand || (search && args[3].Length == 0)) {
    Console.Error.WriteLine("Usage: aot-atlas <extract|inspect|sections|metadata|maps|types|methods|dispatch|dictionaries|runtime-helpers|properties|statics|fields|frozen|enums|gvm|marshalling|pinvoke|code|strings|resources|linkage|unwind|exceptions> <binary> <output.json> [--map-format legacy|metadata]");
    Console.Error.WriteLine("       aot-atlas search <binary> <output.json> <query> [--map-format legacy|metadata]");
    Console.Error.WriteLine("       aot-atlas header <binary> <output.h> [--map-format legacy|metadata]");
    Console.Error.WriteLine("       aot-atlas dispatch-cells <binary> <output.json> [--map-format legacy|metadata]");
    Console.Error.WriteLine("       aot-atlas resolve-dispatch <binary> <output.json> <receiver-VA-hex> <interface-VA-hex> <slot-decimal> [--map-format legacy|metadata]");
    return 2;
}

string temporaryOutput = args[2] + "." + Guid.NewGuid().ToString("N") + ".tmp";
try {
    long start = Stopwatch.GetTimestamp();
    var image = new PeImage(File.ReadAllBytes(args[1]));
    string inputSha256 = Convert.ToHexStringLower(SHA256.HashData(image.FileData));
    long loaded = Stopwatch.GetTimestamp();

    if (args[0] == "unwind") {
        var unwind = new UnwindTables(image);
        double seconds = Stopwatch.GetElapsedTime(loaded).TotalSeconds;
        using (var stream = File.Create(temporaryOutput))
        using (var json = new Utf8JsonWriter(stream, new JsonWriterOptions { Indented = true }))
            UnwindOutput.Write(json, inputSha256, image, unwind);

        File.Move(temporaryOutput, args[2], overwrite: true);
        Console.WriteLine($"{unwind.DirectoryCount} runtime functions, {unwind.Infos.Count} unwind records; {seconds * 1000:F3} ms.");
        return 0;
    }

    if (args[0] == "linkage") {
        var linkage = new PeLinkage(image);
        double seconds = Stopwatch.GetElapsedTime(loaded).TotalSeconds;
        using (var stream = File.Create(temporaryOutput))
        using (var json = new Utf8JsonWriter(stream, new JsonWriterOptions { Indented = true }))
            LinkageOutput.Write(json, inputSha256, image, linkage);

        File.Move(temporaryOutput, args[2], overwrite: true);
        Console.WriteLine($"{linkage.Imports.Count} imports, {linkage.Exports.Length} export slots; {seconds * 1000:F3} ms.");
        return 0;
    }

    var rtr = ReadyToRun.Read(image);
    long parsed = Stopwatch.GetTimestamp();

    if (args[0] == "sections") {
        using (var stream = File.Create(temporaryOutput))
        using (var json = new Utf8JsonWriter(stream, new JsonWriterOptions { Indented = true }))
            SectionsOutput.Write(json, inputSha256, image, rtr);

        File.Move(temporaryOutput, args[2], overwrite: true);
        Console.WriteLine($"{rtr.Sections.Length} RTR section records; {Stopwatch.GetElapsedTime(start).TotalMilliseconds:F3} ms.");
        return 0;
    }

    if (args[0] == "extract") {
        using (var stream = File.Create(temporaryOutput))
        using (var json = new Utf8JsonWriter(stream, new JsonWriterOptions { Indented = true }))
            ExtractCommand.Write(json, inputSha256, image, rtr, requestedFormat);

        File.Move(temporaryOutput, args[2], overwrite: true);
        Console.WriteLine($"Extracted RTR {rtr.Major}.{rtr.Minor}; {Stopwatch.GetElapsedTime(start).TotalMilliseconds:F3} ms.");
        return 0;
    }

    if (args[0] == "strings") {
        long allocated = GC.GetAllocatedBytesForCurrentThread();
        var strings = new NativeStrings(image, rtr.Sections);
        allocated = GC.GetAllocatedBytesForCurrentThread() - allocated;
        double seconds = Stopwatch.GetElapsedTime(parsed).TotalSeconds;
        using (var stream = File.Create(temporaryOutput))
        using (var json = new Utf8JsonWriter(stream, new JsonWriterOptions { Indented = true }))
            StringsOutput.Write(json, inputSha256, image, strings, seconds, allocated);
        File.Move(temporaryOutput, args[2], overwrite: true);
        Console.WriteLine($"{strings.Items.Count} string candidates, {strings.ScannedBytes} bytes; {seconds * 1000:F3} ms.");
        return 0;
    }

    if (args[0] == "exceptions") {
        var unwind = new UnwindTables(image);
        var managed = new ManagedUnwind(image, unwind, new PeDebug(image));
        double seconds = Stopwatch.GetElapsedTime(parsed).TotalSeconds;
        using (var stream = File.Create(temporaryOutput))
        using (var json = new Utf8JsonWriter(stream, new JsonWriterOptions { Indented = true }))
            ExceptionsOutput.Write(json, inputSha256, image, unwind, managed);

        File.Move(temporaryOutput, args[2], overwrite: true);
        Console.WriteLine($"Managed region: {managed.RegionSource}; {managed.Frames.Length} frames, {managed.Clauses.Length} exception clauses; {seconds * 1000:F3} ms.");
        return 0;
    }

    if (args[0] == "resources") {
        var resources = new ResourceMap(image, rtr);
        double seconds = Stopwatch.GetElapsedTime(parsed).TotalSeconds;
        using (var stream = File.Create(temporaryOutput))
        using (var json = new Utf8JsonWriter(stream, new JsonWriterOptions { Indented = true }))
            ResourcesOutput.Write(json, inputSha256, image, resources, seconds);

        File.Move(temporaryOutput, args[2], overwrite: true);
        Console.WriteLine($"{resources.Entries.Count} resources, {resources.Data.Length} bytes; {seconds * 1000:F3} ms.");
        return 0;
    }

    if (needsMetadata) {
        var section = rtr.Find(313);
        var metadata = new Metadata(section.Length == 0 ? default : image.FileMemory(section.Start, checked((int)section.Length)),
            rtr.MetadataHandleBits, rtr.Major < 10);
        long metadataStart = Stopwatch.GetTimestamp();
        metadata.ReadDefinitions();
        var members = args[0] == "metadata" ? new MetadataMembers(metadata) : null;
        long metadataEnd = Stopwatch.GetTimestamp();

        if (needsMaps) {
            var fixups = RuntimeTables.Fixups(image, rtr.Find(308));
            var maps = new ReflectionMaps();
            maps.Read(image, rtr, metadata, fixups, requestedFormat);
            long mapsEnd = Stopwatch.GetTimestamp();

            if (needsExtraction) {
                var extraction = new Extraction(image, rtr, metadata, maps, fixups);
                if (command == "header") {
                    (int Types, int Fields, int References, int Unknown) counts;
                    using (var writer = new StreamWriter(temporaryOutput, false, new System.Text.UTF8Encoding(false), 64 * 1024)) {
                        writer.NewLine = "\n";
                        counts = HeaderOutput.Write(writer, inputSha256, extraction);
                    }

                    File.Move(temporaryOutput, args[2], overwrite: true);
                    Console.WriteLine($"{counts.Types} layouts, {counts.Fields} fields, {counts.References} GC slots, {counts.Unknown} unknown-size offsets; {Stopwatch.GetElapsedTime(start).TotalMilliseconds:F3} ms.");
                    return 0;
                }

                if (search) {
                    int hits;
                    using (var stream = File.Create(temporaryOutput))
                    using (var json = new Utf8JsonWriter(stream, new JsonWriterOptions { Indented = true }))
                        hits = SearchOutput.Write(json, inputSha256, extraction, args[3]);

                    File.Move(temporaryOutput, args[2], overwrite: true);
                    Console.WriteLine($"{hits} search results; {Stopwatch.GetElapsedTime(start).TotalMilliseconds:F3} ms.");
                    return 0;
                }

                if (args[0] == "code") {
                    long codeStart = Stopwatch.GetTimestamp(), allocated = GC.GetAllocatedBytesForCurrentThread();
                    var code = new CodeFlow(extraction, new ManagedAbi(extraction));
                    allocated = GC.GetAllocatedBytesForCurrentThread() - allocated;
                    double seconds = Stopwatch.GetElapsedTime(codeStart).TotalSeconds;
                    using (var stream = File.Create(temporaryOutput))
                    using (var json = new Utf8JsonWriter(stream, new JsonWriterOptions { Indented = true }))
                        CodeOutput.Write(json, inputSha256, extraction, code, seconds, allocated);

                    File.Move(temporaryOutput, args[2], overwrite: true);
                    Console.WriteLine($"{code.InstructionCount} instructions, {code.Calls.Count} calls, {code.Addresses.Count} address references; {seconds * 1000:F3} ms.");
                    return 0;
                }

                using (var stream = File.Create(temporaryOutput))
                using (var json = new Utf8JsonWriter(stream, new JsonWriterOptions { Indented = true })) {
                    switch (args[0]) {
                        case "dictionaries":
                            DictionariesOutput.Write(json, inputSha256, extraction);
                            break;
                        case "dispatch-cells":
                            var dispatchCode = new CodeFlow(extraction, new ManagedAbi(extraction));
                            long dispatchStart = Stopwatch.GetTimestamp();
                            var dispatchCells = new DispatchCells(extraction, dispatchCode);
                            DispatchCellsOutput.Write(json, inputSha256, extraction, dispatchCells, Stopwatch.GetElapsedTime(dispatchStart).TotalSeconds);
                            break;
                        case "resolve-dispatch":
                            if (!ulong.TryParse(args[3].AsSpan(args[3].StartsWith("0x", StringComparison.OrdinalIgnoreCase) ? 2 : 0),
                                    System.Globalization.NumberStyles.HexNumber, System.Globalization.CultureInfo.InvariantCulture, out ulong receiver)
                                || !ulong.TryParse(args[4].AsSpan(args[4].StartsWith("0x", StringComparison.OrdinalIgnoreCase) ? 2 : 0),
                                    System.Globalization.NumberStyles.HexNumber, System.Globalization.CultureInfo.InvariantCulture, out ulong contract)
                                || !ushort.TryParse(args[5], System.Globalization.NumberStyles.None,
                                    System.Globalization.CultureInfo.InvariantCulture, out ushort slot))
                                throw new InvalidDataException("Dispatch resolution requires hexadecimal receiver/interface VAs and a decimal slot from 0 to 65535.");
                            DispatchCellsOutput.WriteResolution(json, inputSha256, extraction, receiver, contract, slot);
                            break;
                        case "runtime-helpers":
                            var helperCode = new CodeFlow(extraction, new ManagedAbi(extraction));
                            RuntimeHelpersOutput.Write(json, inputSha256, new RuntimeHelpers(extraction, helperCode));
                            break;
                        case "properties":
                            var propertyAbi = new ManagedAbi(extraction);
                            PropertyOutput.Write(json, inputSha256, extraction, new PropertyProjections(extraction, propertyAbi));
                            break;
                        case "types":
                            TypesOutput.Write(json, inputSha256, extraction.Types, extraction.Gc, extraction.Names, image, extraction.TypesSeconds);
                            break;
                        case "methods":
                            long abiStart = Stopwatch.GetTimestamp();
                            var abi = new ManagedAbi(extraction);
                            MethodsOutput.Write(json, inputSha256, extraction, abi, Stopwatch.GetElapsedTime(abiStart).TotalSeconds);
                            break;
                        case "dispatch":
                            DispatchOutput.Write(json, inputSha256, image, extraction.Types, extraction.Names, extraction.Dispatch, extraction.Virtuals, extraction.DispatchSeconds);
                            break;
                        case "marshalling":
                            MarshallingOutput.Write(json, inputSha256, extraction);
                            break;
                        case "pinvoke":
                            PInvokeOutput.Write(json, inputSha256, extraction);
                            break;
                        case "gvm":
                            GvmOutput.Write(json, inputSha256, extraction);
                            break;
                        case "frozen":
                            FrozenOutput.Write(json, inputSha256, extraction);
                            break;
                        case "enums":
                            EnumsOutput.Write(json, inputSha256, extraction);
                            break;
                        case "fields":
                            FieldsOutput.Write(json, inputSha256, extraction);
                            break;
                        case "statics":
                            StaticsOutput.Write(json, inputSha256, extraction);
                            break;
                    }
                }

                File.Move(temporaryOutput, args[2], overwrite: true);
                Console.WriteLine($"{extraction.Types.Types.Count} MethodTables, {extraction.Dispatch.Targets.Count} dispatch targets, {extraction.Statics.Allocations.Count} static allocation layouts; {(extraction.TypesSeconds + extraction.DispatchSeconds) * 1000:F3} ms.");
                return 0;
            }

            using (var stream = File.Create(temporaryOutput))
            using (var json = new Utf8JsonWriter(stream, new JsonWriterOptions { Indented = true }))
                MapsOutput.Write(json, inputSha256, maps, image, metadata, Stopwatch.GetElapsedTime(metadataEnd, mapsEnd).TotalSeconds);

            File.Move(temporaryOutput, args[2], overwrite: true);
            Console.WriteLine($"{maps.Format}: {maps.Types.Count} named types, {maps.DerivedTypes.Count} derived types, {maps.Methods.Count} invoke entries, {maps.Fields.Count} fields; {Stopwatch.GetElapsedTime(metadataEnd, mapsEnd).TotalMilliseconds:F3} ms.");
            return 0;
        }

        using (var stream = File.Create(temporaryOutput))
        using (var json = new Utf8JsonWriter(stream, new JsonWriterOptions { Indented = true }))
            MetadataOutput.Write(json, inputSha256, metadata, members!, image, rtr, Stopwatch.GetElapsedTime(metadataStart, metadataEnd).TotalSeconds);

        File.Move(temporaryOutput, args[2], overwrite: true);
        Console.WriteLine($"{metadata.Scopes.Count} scopes, {metadata.Types.Count} types, {metadata.Methods.Count} method records, {metadata.Fields.Count} field records; {Stopwatch.GetElapsedTime(metadataStart, metadataEnd).TotalMilliseconds:F3} ms.");
        return 0;
    }

    var hydration = Hydration.Read(image, rtr);
    long hydrated = Stopwatch.GetTimestamp();

    var functions = RuntimeTables.Functions(image);
    var commonFixups = RuntimeTables.Fixups(image, rtr.Find(308));
    var nativeReferences = RuntimeTables.Fixups(image, rtr.Find(331));
    var nativeStatics = RuntimeTables.Fixups(image, rtr.Find(333));
    long finished = Stopwatch.GetTimestamp();

    using (var stream = File.Create(temporaryOutput))
    using (var json = new Utf8JsonWriter(stream, new JsonWriterOptions { Indented = true }))
        InspectOutput.Write(json, inputSha256, image, rtr, hydration, functions, commonFixups, nativeReferences, nativeStatics,
            [Stopwatch.GetElapsedTime(start, loaded).TotalSeconds, Stopwatch.GetElapsedTime(loaded, parsed).TotalSeconds,
             Stopwatch.GetElapsedTime(parsed, hydrated).TotalSeconds, Stopwatch.GetElapsedTime(hydrated, finished).TotalSeconds,
             Stopwatch.GetElapsedTime(start, finished).TotalSeconds]);

    File.Move(temporaryOutput, args[2], overwrite: true);
    Console.WriteLine($"RTR {rtr.Major}.{rtr.Minor}: {rtr.Sections.Length} sections, {hydration.Length} hydrated bytes, {functions.Length} runtime functions.");
    return 0;
} catch (Exception error) when (error is IOException or UnauthorizedAccessException or InvalidDataException or NotSupportedException or OverflowException or System.Text.DecoderFallbackException) {
    Console.Error.WriteLine(error.Message);
    return 1;
} finally {
    if (File.Exists(temporaryOutput))
        File.Delete(temporaryOutput);
}
