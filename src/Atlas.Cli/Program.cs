using System.Diagnostics;
using System.Security.Cryptography;
using Atlas;

long invocationStart = Stopwatch.GetTimestamp();
long invocationAllocated = GC.GetAllocatedBytesForCurrentThread();
long invocationProcessAllocated = GC.GetTotalAllocatedBytes(precise: true);
MapFormat requestedFormat = MapFormat.Auto;

string command = args.Length == 0 ? "" : args[0];
var plan = CommandPlan.For(command);
if (plan is null)
    return Usage();

bool search = command == "search";
int positionalCount = plan.PositionalCount;
bool validArguments = args.Length == positionalCount;

if (args.Length == positionalCount + 2
    && plan.AcceptsMapFormat
    && args[positionalCount] == "--map-format") {
    requestedFormat = args[positionalCount + 1] switch {
        "legacy" => MapFormat.Legacy,
        "metadata" => MapFormat.Metadata,
        _ => MapFormat.Auto
    };

    validArguments = requestedFormat != MapFormat.Auto;
}

if (!validArguments || (search && args[3].Length == 0))
    return Usage();

string temporaryOutput = args[2] + "." + Guid.NewGuid().ToString("N") + ".tmp";
using var cancellation = new CancellationTokenSource();
CancellationToken cancellationToken = cancellation.Token;
Console.CancelKeyPress += Cancel;

AnalysisMeasurement totalMeasurement = default;
long totalProcessAllocated = 0;
bool outputPublished = false;
double readSeconds = 0;
double hashSeconds = 0;
double headerSeconds = 0;

try {
    long start = Stopwatch.GetTimestamp();

    cancellationToken.ThrowIfCancellationRequested();
    var image = PeImage.ReadFile(args[1]);
    readSeconds = Stopwatch.GetElapsedTime(start).TotalSeconds;
    cancellationToken.ThrowIfCancellationRequested();

    long hashStart = Stopwatch.GetTimestamp();
    string inputSha256 = Convert.ToHexStringLower(SHA256.HashData(image.FileData));
    hashSeconds = Stopwatch.GetElapsedTime(hashStart).TotalSeconds;
    cancellationToken.ThrowIfCancellationRequested();
    long loaded = Stopwatch.GetTimestamp();

    if (args[0] == "unwind") {
        var unwind = new UnwindTables(image, cancellationToken);

        using (var stream = new OutputFileStream(temporaryOutput))
        using (var json = JsonOutput.CreateWriter(stream, cancellationToken))
            UnwindOutput.Write(json, inputSha256, image, unwind);

        PublishOutput();
        Console.WriteLine($"{unwind.DirectoryCount} runtime functions, {unwind.Infos.Count} unwind records.");

        return 0;
    }

    if (args[0] == "linkage") {
        var linkage = new PeLinkage(image);

        using (var stream = new OutputFileStream(temporaryOutput))
        using (var json = JsonOutput.CreateWriter(stream, cancellationToken))
            LinkageOutput.Write(json, inputSha256, image, linkage);

        PublishOutput();
        Console.WriteLine($"{linkage.Imports.Count} imports, {linkage.Exports.Length} export slots.");

        return 0;
    }

    var rtr = ReadyToRun.Read(image);
    headerSeconds = Stopwatch.GetElapsedTime(loaded).TotalSeconds;
    cancellationToken.ThrowIfCancellationRequested();
    long parsed = Stopwatch.GetTimestamp();

    if (args[0] == "sections") {
        using (var stream = new OutputFileStream(temporaryOutput))
        using (var json = JsonOutput.CreateWriter(stream, cancellationToken))
            SectionsOutput.Write(json, inputSha256, image, rtr);

        PublishOutput();
        Console.WriteLine($"{rtr.Sections.Length} RTR section records.");

        return 0;
    }

    if (args[0] == "extract") {
        using (var stream = new OutputFileStream(temporaryOutput))
        using (var json = JsonOutput.CreateWriter(stream, cancellationToken))
            ExtractCommand.Write(json, inputSha256, image, rtr, requestedFormat, cancellationToken);

        PublishOutput();
        Console.WriteLine($"Extracted RTR {rtr.Major}.{rtr.Minor}.");

        return 0;
    }

    if (args[0] == "strings") {
        long allocated = GC.GetAllocatedBytesForCurrentThread();

        var strings = new NativeStrings(image, rtr.Sections, cancellationToken);

        allocated = GC.GetAllocatedBytesForCurrentThread() - allocated;
        double seconds = Stopwatch.GetElapsedTime(parsed).TotalSeconds;

        using (var stream = new OutputFileStream(temporaryOutput))
        using (var json = JsonOutput.CreateWriter(stream, cancellationToken))
            StringsOutput.Write(json, inputSha256, image, strings, seconds, allocated, cancellationToken);

        PublishOutput();
        Console.WriteLine($"{strings.Items.Count} string candidates, {strings.ScannedBytes} bytes.");

        return 0;
    }

    if (command == "runtime-helpers") {
        var memory = new RuntimeMemory(image, Hydration.Read(image, rtr, cancellationToken));
        var unwind = new UnwindTables(image, cancellationToken);
        var helpers = new RuntimeHelpers(image, rtr, memory, unwind, cancellationToken);

        using (var stream = new OutputFileStream(temporaryOutput))
        using (var json = JsonOutput.CreateWriter(stream, cancellationToken))
            RuntimeHelpersOutput.Write(json, inputSha256, helpers);

        PublishOutput();
        Console.WriteLine($"{helpers.Status}: {helpers.Helpers.Length} runtime helpers.");

        return 0;
    }

    if (command == "fat-function-pointers") {
        var memory = new RuntimeMemory(image, Hydration.Read(image, rtr, cancellationToken));
        var analysis = new UnwindAnalysis(image, rtr, memory, cancellationToken);
        MethodGcMap? gc = analysis.Unwind is { } unwind && analysis.Managed is { } managed
            ? new MethodGcMap(image, rtr, unwind, managed, cancellationToken) : null;

        var delegates = ReadDelegateConsumers(image, rtr);
        var pointers = new FatFunctionPointers(image, rtr, memory, analysis.Unwind, gc, delegates.Consumers, cancellationToken);

        using (var stream = new OutputFileStream(temporaryOutput))
        using (var json = JsonOutput.CreateWriter(stream, cancellationToken))
            FatFunctionPointersOutput.Write(json, inputSha256, image, analysis, gc, pointers, delegates.Status, delegates.Error);

        PublishOutput();
        Console.WriteLine($"{pointers.Values.Count} fat function pointers, {pointers.References.Count} references.");

        return 0;
    }

    if (command == "generic-context") {
        var memory = new RuntimeMemory(image, Hydration.Read(image, rtr, cancellationToken));
        var analysis = new UnwindAnalysis(image, rtr, memory, cancellationToken);
        var unwind = analysis.RequireUnwind();
        var managed = analysis.RequireManaged();
        var gc = new MethodGcMap(image, rtr, unwind, managed, cancellationToken);
        var delegates = ReadDelegateConsumers(image, rtr);
        DictionarySlotConsumers consumers = new(image, memory, unwind, gc, delegates.Consumers, cancellationToken);
        GenericContextReferences references = consumers.ContextReferences;

        using (var stream = new OutputFileStream(temporaryOutput))
        using (var json = JsonOutput.CreateWriter(stream, cancellationToken))
            GenericContextOutput.Write(json, inputSha256, image, managed, gc, references, consumers,
                delegates.Status, delegates.Error);

        PublishOutput();
        Console.WriteLine($"{references.Values.Count} method dictionary references, {references.Parameters.Length}/{references.DeclaredMethodContexts} context parameters.");

        return 0;
    }

    if (command is "exceptions" or "gcinfo") {
        var memory = new RuntimeMemory(image, Hydration.Read(image, rtr, cancellationToken));
        var analysis = new UnwindAnalysis(image, rtr, memory, cancellationToken);
        var unwind = analysis.RequireUnwind();
        var managed = analysis.RequireManaged();

        foreach (var failure in analysis.Failures)
            Console.Error.WriteLine($"{AnalysisOutput.PhaseName(failure.Phase)}: {failure.Error}");

        var gcInfo = command == "gcinfo" ? new MethodGcMap(image, rtr, unwind, managed, cancellationToken) : null;

        using (var stream = new OutputFileStream(temporaryOutput))
        using (var json = JsonOutput.CreateWriter(stream, cancellationToken)) {
            if (gcInfo is not null)
                GcInfoOutput.Write(json, inputSha256, image, managed, gcInfo, cancellationToken);
            else
                ExceptionsOutput.Write(json, inputSha256, image, unwind, managed);
        }

        PublishOutput();
        if (gcInfo is not null)
            Console.WriteLine($"{gcInfo.Methods.Length} GC methods, {gcInfo.Methods.Count(method => method.Error is not null)} unavailable.");
        else
            Console.WriteLine($"Managed region: {managed.RegionSource}; {managed.Frames.Length} frames, {managed.Clauses.Length} exception clauses.");

        return 0;
    }

    if (args[0] == "resources") {
        long resourceStart = Stopwatch.GetTimestamp();
        var resources = new ResourceMap(image, rtr);
        double seconds = Stopwatch.GetElapsedTime(resourceStart).TotalSeconds;

        using (var stream = new OutputFileStream(temporaryOutput))
        using (var json = JsonOutput.CreateWriter(stream, cancellationToken))
            ResourcesOutput.Write(json, inputSha256, image, resources, seconds);

        PublishOutput();
        Console.WriteLine($"{resources.Entries.Count} resources, {resources.Data.Length} bytes.");

        return 0;
    }

    if (plan.NeedsMetadata) {
        long metadataStart = Stopwatch.GetTimestamp();
        var metadataBuilder = MetadataBuilder.FromImage(image, rtr, cancellationToken);
        metadataBuilder.ReadDefinitions(cancellationToken);

        long metadataEnd = Stopwatch.GetTimestamp();

        if (plan.NeedsMaps) {
            var fixups = RuntimeTables.Fixups(image, rtr.Find(RtrSectionId.CommonFixupsTable));
            var maps = new ReflectionMaps();

            maps.Read(image, rtr, metadataBuilder, fixups, requestedFormat, cancellationToken);

            long mapsEnd = Stopwatch.GetTimestamp();

            if (plan.Stages is { } stages) {
                var products = plan.Products == AnalysisProduct.None ? null
                    : new AnalysisProducts(image, rtr, metadataBuilder, maps, fixups,
                        requested: plan.Products, stages: stages, cancellationToken: cancellationToken);
                var extraction = products?.Extraction
                    ?? new Extraction(image, rtr, metadataBuilder, maps, fixups, stages, cancellationToken);
                var metadata = extraction.Metadata;
                maps = extraction.Maps;

                foreach (var failure in extraction.UnwindAnalysis.Failures)
                    Console.Error.WriteLine($"{AnalysisOutput.PhaseName(failure.Phase)}: {failure.Error}");

                if (extraction.UnwindAnalysis.Managed is null)
                    Console.Error.WriteLine("Exception-only type evidence unavailable.");

                if (command == "header") {
                    (int Types, int Fields, int References, int Unknown) counts;

                    using (var stream = new OutputFileStream(temporaryOutput))
                    using (var writer = new StreamWriter(
                        stream, new System.Text.UTF8Encoding(false), 64 * 1024, leaveOpen: true)) {
                        writer.NewLine = "\n";

                        counts = HeaderOutput.Write(writer, inputSha256, extraction);
                    }

                    PublishOutput();
                    Console.WriteLine($"{counts.Types} layouts, {counts.Fields} fields, {counts.References} GC slots, {counts.Unknown} unknown-size offsets.");

                    return 0;
                }

                if (search) {
                    int hits;

                    using (var stream = new OutputFileStream(temporaryOutput))
                    using (var json = JsonOutput.CreateWriter(stream, cancellationToken))
                        hits = SearchOutput.Write(json, inputSha256, products!, args[3]);

                    PublishOutput();
                    Console.WriteLine($"{hits} search results.");

                    return 0;
                }

                if (args[0] == "code") {
                    var code = products!.Code ?? throw new InvalidDataException("Managed code analysis is unavailable.");
                    long allocated = products.CodeMeasurement.AllocatedBytes;
                    double seconds = products.CodeMeasurement.Seconds;

                    using (var stream = new OutputFileStream(temporaryOutput))
                    using (var json = JsonOutput.CreateWriter(stream, cancellationToken))
                        CodeOutput.Write(json, inputSha256, extraction, code, seconds, allocated);

                    PublishOutput();
                    Console.WriteLine($"{code.InstructionCount} instructions, {code.Calls.Count} calls, {code.Addresses.Count} address references.");

                    return 0;
                }

                using (var stream = new OutputFileStream(temporaryOutput))
                using (var json = JsonOutput.CreateWriter(stream, cancellationToken)) {
                    switch (args[0]) {
                        case "templates":
                            TemplatesOutput.Write(json, inputSha256, extraction, cancellationToken);
                            break;

                        case "dictionaries":
                            DictionariesOutput.Write(json, inputSha256, extraction);
                            break;

                        case "dispatch-cells":
                            var dispatchCells = products!.DispatchCells
                                ?? throw new InvalidDataException("Managed dispatch-cell analysis is unavailable.");

                            DispatchCellsOutput.Write(
                                json, inputSha256, extraction, dispatchCells,
                                products.DispatchCellMeasurement.Seconds);
                            break;

                        case "resolve-dispatch":
                            if (!ulong.TryParse(
                                    args[3].AsSpan(args[3].StartsWith("0x", StringComparison.OrdinalIgnoreCase) ? 2 : 0),
                                    System.Globalization.NumberStyles.HexNumber,
                                    System.Globalization.CultureInfo.InvariantCulture,
                                    out ulong receiver)
                                || !ulong.TryParse(
                                    args[4].AsSpan(args[4].StartsWith("0x", StringComparison.OrdinalIgnoreCase) ? 2 : 0),
                                    System.Globalization.NumberStyles.HexNumber,
                                    System.Globalization.CultureInfo.InvariantCulture,
                                    out ulong contract)
                                || !ushort.TryParse(
                                    args[5], System.Globalization.NumberStyles.None,
                                    System.Globalization.CultureInfo.InvariantCulture,
                                    out ushort slot))
                                throw new InvalidDataException("Dispatch resolution requires hexadecimal receiver/interface VAs and a decimal slot from 0 to 65535.");

                            DispatchCellsOutput.WriteResolution(
                                json, inputSha256, extraction, receiver, contract, slot);
                            break;

                        case "properties":
                            var properties = products!.Properties
                                ?? throw new InvalidDataException("Managed property analysis is unavailable.");

                            PropertyOutput.Write(
                                json, inputSha256, extraction, properties);
                            break;

                        case "types":
                            TypesOutput.Write(json, inputSha256, extraction);
                            break;

                        case "methods":
                            var abi = products!.Abi ?? throw new InvalidDataException("Managed ABI analysis is unavailable.");

                            MethodsOutput.Write(json, inputSha256, extraction, abi,
                                products.AbiMeasurement.Seconds, cancellationToken);
                            break;

                        case "dispatch":
                            DispatchOutput.Write(json, inputSha256, extraction);
                            break;

                        case "marshalling":
                            MarshallingOutput.Write(json, inputSha256, extraction);
                            break;

                        case "typemaps":
                            TypeMapsOutput.Write(json, inputSha256, extraction, cancellationToken);
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

                PublishOutput();
                Console.WriteLine($"{extraction.Types.Types.Count} MethodTables, {extraction.Statics.Allocations.Count} static allocation layouts.");

                return 0;
            }

            var mapsMetadata = metadataBuilder.Publish(cancellationToken);
            maps.SetSignatureOrigin(mapsMetadata.PublishedSignatures);

            using (var stream = new OutputFileStream(temporaryOutput))
            using (var json = JsonOutput.CreateWriter(stream, cancellationToken))
                MapsOutput.Write(json, inputSha256, maps, image, mapsMetadata,
                    Stopwatch.GetElapsedTime(metadataEnd, mapsEnd).TotalSeconds, cancellationToken);

            PublishOutput();
            Console.WriteLine($"{maps.Format}: {maps.Types.Count} named types, {maps.DerivedTypes.Count} derived types, {maps.Methods.Count} invoke entries, {maps.Fields.Count} fields.");

            return 0;
        }

        var publishedMetadata = metadataBuilder.Publish(cancellationToken);
        metadataEnd = Stopwatch.GetTimestamp();

        using (var stream = new OutputFileStream(temporaryOutput))
        using (var json = JsonOutput.CreateWriter(stream, cancellationToken))
            MetadataOutput.Write(json, inputSha256, publishedMetadata,
                Stopwatch.GetElapsedTime(metadataStart, metadataEnd).TotalSeconds, cancellationToken: cancellationToken);

        PublishOutput();
        Console.WriteLine($"{publishedMetadata.ScopeDefinitions.Length} scopes, {publishedMetadata.TypeDefinitions.Length} types, {publishedMetadata.MethodDefinitions.Length} method records, {publishedMetadata.FieldDefinitions.Length} field records.");

        return 0;
    }

    var hydration = Hydration.Read(image, rtr, cancellationToken);
    long hydrated = Stopwatch.GetTimestamp();

    var functions = RuntimeTables.Functions(image);

    var commonFixups = RuntimeTables.Fixups(image, rtr.Find(RtrSectionId.CommonFixupsTable));
    var nativeReferences = RuntimeTables.Fixups(image, rtr.Find(RtrSectionId.NativeReferences));
    var nativeStatics = RuntimeTables.Fixups(image, rtr.Find(RtrSectionId.NativeStatics));

    long finished = Stopwatch.GetTimestamp();

    using (var stream = new OutputFileStream(temporaryOutput))
    using (var json = JsonOutput.CreateWriter(stream, cancellationToken))
        InspectOutput.Write(
            json, inputSha256, image, rtr, hydration, functions, commonFixups, nativeReferences, nativeStatics,
            [
                Stopwatch.GetElapsedTime(start, loaded).TotalSeconds,
                Stopwatch.GetElapsedTime(loaded, parsed).TotalSeconds,
                Stopwatch.GetElapsedTime(parsed, hydrated).TotalSeconds,
                Stopwatch.GetElapsedTime(hydrated, finished).TotalSeconds,
                Stopwatch.GetElapsedTime(start, finished).TotalSeconds
            ]);

    PublishOutput();
    Console.WriteLine($"RTR {rtr.Major}.{rtr.Minor}: {rtr.Sections.Length} sections, {hydration.Length} hydrated bytes, {functions.Length} runtime functions.");

    return 0;
} catch (OperationCanceledException) {
    Console.Error.WriteLine("Cancelled.");

    return 2;
} catch (Exception error) when (error is IOException or UnauthorizedAccessException
    or InvalidDataException or NotSupportedException or OverflowException
    or System.Text.DecoderFallbackException) {
    Console.Error.WriteLine(error.Message);

    return 1;
} finally {
    Console.CancelKeyPress -= Cancel;

    if (File.Exists(temporaryOutput))
        File.Delete(temporaryOutput);

    if (outputPublished)
        Console.Error.WriteLine($"Total {totalMeasurement.Seconds * 1000:F3} ms; process managed allocation delta {totalProcessAllocated:N0} B, "
            + $"operation-thread allocation {totalMeasurement.AllocatedBytes:N0} B; "
            + $"read {readSeconds * 1000:F3} ms, hash {hashSeconds * 1000:F3} ms, RTR header {headerSeconds * 1000:F3} ms.");
}

int Usage() {
    Console.Error.WriteLine("Usage: aot-atlas <extract|inspect|sections|metadata|maps|types|methods|dispatch|dictionaries|runtime-helpers|properties|templates|statics|fields|frozen|enums|gvm|marshalling|typemaps|pinvoke|code|strings|resources|linkage|unwind|exceptions|gcinfo|generic-context|fat-function-pointers> <binary> <output.json> [--map-format legacy|metadata]");
    Console.Error.WriteLine("       aot-atlas search <binary> <output.json> <query> [--map-format legacy|metadata]");
    Console.Error.WriteLine("       aot-atlas header <binary> <output.h> [--map-format legacy|metadata]");
    Console.Error.WriteLine("       aot-atlas dispatch-cells <binary> <output.json> [--map-format legacy|metadata]");
    Console.Error.WriteLine("       aot-atlas resolve-dispatch <binary> <output.json> <receiver-VA-hex> <interface-VA-hex> <slot-decimal> [--map-format legacy|metadata]");

    return 2;
}

void Cancel(object? sender, ConsoleCancelEventArgs eventArgs) {
    eventArgs.Cancel = true;
    cancellation.Cancel();
}

(FunctionPointerConsumer[] Consumers, string Status, string? Error) ReadDelegateConsumers(PeImage image, ReadyToRun rtr) {
    cancellationToken.ThrowIfCancellationRequested();

    // Optional trace identities belong to private parser state.
    try {
        var section = rtr.Find(RtrSectionId.EmbeddedMetadata);
        if (section.Length == 0)
            return ([], "unavailable", null);

        var metadataBuilder = MetadataBuilder.FromImage(image, rtr, cancellationToken);
        metadataBuilder.ReadDefinitions(cancellationToken);

        var traces = new TraceMaps(image, rtr, metadataBuilder,
            RuntimeTables.Fixups(image, rtr.Find(RtrSectionId.CommonFixupsTable)), cancellationToken);
        var metadata = metadataBuilder.Publish(cancellationToken);
        traces.Publish(metadata.PublishedSignatures, cancellationToken);
        var consumers = ManagedFunctionPointerConsumers.Read(
            metadata, traces, metadata.PublishedSignatures, cancellationToken);

        return (consumers, traces.Methods.Count == 0 ? "unavailable" : "complete", null);
    } catch (Exception error) when (error is InvalidDataException or NotSupportedException or OverflowException) {
        return ([], "unavailable", error.Message);
    }
}

void PublishOutput() {
    cancellationToken.ThrowIfCancellationRequested();
    File.Move(temporaryOutput, args[2], overwrite: true);
    totalMeasurement = AnalysisMeasurement.Since(invocationStart, invocationAllocated);
    totalProcessAllocated = GC.GetTotalAllocatedBytes(precise: true) - invocationProcessAllocated;
    outputPublished = true;
}
