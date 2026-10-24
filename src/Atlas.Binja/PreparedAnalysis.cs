namespace Atlas.Binja;

internal sealed class PreparedAnalysis {
    internal AnalysisProducts Products { get; }
    internal Extraction Extraction => Products.Extraction;
    internal ManagedAbi? ManagedAbi => Products.Abi;
    internal PropertyProjections? Properties => Products.Properties;
    internal CodeFlow? Code => Products.Code;
    internal DispatchCells? DispatchCells => Products.DispatchCells;
    internal RuntimeHelpers? Helpers => Products.Helpers;
    internal MethodGcMap? GcInfo => Products.GcInfo;
    internal GenericContextReferences? GenericContexts => Products.GenericContexts;
    internal FatFunctionPointers FunctionPointers => Products.RequireFunctionPointers();
    internal NativeStrings Strings => Products.RequireStrings();
    internal ReadOnlySpan<CodeEdge> StringReferences => Products.StringReferences;

    internal static PreparedAnalysis Read(PeImage image, MapFormat mapFormat = MapFormat.Auto,
        CancellationToken cancellationToken = default) =>
        new(AnalysisProducts.Read(image, mapFormat: mapFormat, cancellationToken: cancellationToken), cancellationToken);

    internal PreparedAnalysis(
        PeImage image,
        ReadyToRun header,
        MetadataBuilder metadata,
        ReflectionMaps maps,
        ulong[] fixups,
        CancellationToken cancellationToken = default)
        : this(new AnalysisProducts(image, header, metadata, maps, fixups,
            cancellationToken: cancellationToken), cancellationToken) {
    }

    private PreparedAnalysis(AnalysisProducts products, CancellationToken cancellationToken) {
        cancellationToken.ThrowIfCancellationRequested();
        Products = products;
        var snapshot = Extraction.Metadata;

        // All graph consumers are checked before the host receives any publication.
        ValidateSignatures(snapshot, Extraction.Signatures);
        ValidateSignatures(snapshot, Extraction.Bindings.Signatures);
        if (ManagedAbi is not null)
            ValidateSignatures(snapshot, ManagedAbi.Signatures);

        if (Properties is not null)
            ValidateSignatures(snapshot, Properties.Signatures);

        if (Code is not null && Code.Context.Origins.Text.Span.Contains('\0'))
            throw new InvalidDataException("A contextual function name contains a NUL and cant be represented by a native symbol.");

        foreach (string name in Extraction.Names.Values) {
            if (name.Contains('\0'))
                throw new InvalidDataException("A MethodTable name contains a NUL and cant be represented by a native symbol.");
        }
    }

    internal static void ValidateSignatures(Metadata metadata, Signatures signatures) {
        if (!ReferenceEquals(metadata.PublishedSignatures, signatures))
            throw new ArgumentException("The published signature graph belongs to different metadata.", nameof(signatures));
    }
}
