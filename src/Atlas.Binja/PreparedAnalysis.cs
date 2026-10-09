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
    internal FatFunctionPointers FunctionPointers => Products.FunctionPointers!;
    internal NativeStrings Strings => Products.Strings!;
    internal ReadOnlySpan<CodeEdge> StringReferences => Products.StringReferences;

    internal PreparedAnalysis(
        PeImage image,
        ReadyToRun header,
        Metadata metadata,
        ReflectionMaps maps,
        ulong[] fixups,
        CancellationToken cancellationToken = default) {
        Products = new AnalysisProducts(image, header, metadata, maps, fixups,
            cancellationToken: cancellationToken);
        metadata = Extraction.Metadata;

        // All graph consumers are checked before the host receives any publication.
        ValidateSignatures(metadata, Extraction.Signatures);
        ValidateSignatures(metadata, Extraction.Bindings.Signatures);
        if (ManagedAbi is not null)
            ValidateSignatures(metadata, ManagedAbi.Signatures);

        if (Properties is not null)
            ValidateSignatures(metadata, Properties.Signatures);

        if (Code is not null && Code.Context.Origins.Text.Span.Contains('\0'))
            throw new InvalidDataException("A contextual function name contains a NUL and cant be represented by a native symbol.");

        foreach (string name in Extraction.Names.Values) {
            if (name.Contains('\0'))
                throw new InvalidDataException("A MethodTable name contains a NUL and cant be represented by a native symbol.");
        }
    }

    internal static void ValidateSignatures(Metadata metadata, Signatures signatures) {
        if (!metadata.SignatureBuilder.Owns(signatures))
            throw new ArgumentException("The published signature graph belongs to different metadata.", nameof(signatures));
    }
}
