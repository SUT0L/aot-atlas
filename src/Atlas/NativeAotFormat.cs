namespace Atlas;

// The version has been validated before any consumer interprets format-dependent bits.
public readonly struct NativeAotFormat {
    public readonly ushort Major;
    public readonly ushort Minor;

    private NativeAotFormat(ushort major, ushort minor) {
        Major = major;
        Minor = minor;
    }

    public static NativeAotFormat ForVersion(ushort major, ushort minor) {
        if ((major, minor) is not ((9, 1) or (10, 1) or (12, 0) or (16, 0) or (18, 4) or (18, 5)))
            throw new NotSupportedException($"Unsupported RTR version {major}.{minor}.");

        return new NativeAotFormat(major, minor);
    }

    public int MetadataHandleBits => Major < 12 ? 8 : 7;
    public bool LegacyTypeLayout => Major < 10;
    public bool LegacyMetadataConstants => Major < 10;
    public int MethodGcVersion => Major < 10 ? 2 : Major < 11 ? 3 : 4;
    public uint HasPointersFlag => PointerFlag(LegacyTypeLayout);
    internal static uint PointerFlag(bool legacy) => legacy ? 0x00200000U : 0x01000000U;

    public bool UniversalCanonicalMethods => Major <= 12;
    public bool InstanceConstrainedMethods => Major >= 16;
    public bool LegacyDictionaryRecipes => Major == 9;
    public bool LegacyTemplateMethodSignatures => Major == 9;
    public bool OrdinalFields => Major <= 12;
    public bool AsyncMethodVariants => Major >= 18;
    public bool EmbeddedDehydrationLength => Major > 18 || (Major == 18 && Minor >= 4);
    public bool MaskedGenericMethodTokens => Major > 18 || (Major == 18 && Minor >= 4);

    // RTR 12 requires map evidence; a version hint alone cannot select its grammar.
    public static MapFormat MapGrammar(int major) => major == 12
        ? MapFormat.Auto
        : major < 12 ? MapFormat.Legacy : MapFormat.Metadata;

    public uint InvokeMapFlags(MapFormat grammar) => grammar switch {
        MapFormat.Legacy => 0x70FFU,
        MapFormat.Metadata => UniversalCanonicalMethods ? 0x70FBU : 0x70BBU,
        _ => throw new ArgumentOutOfRangeException(nameof(grammar))
    };

    public uint FieldMapFlags(MapFormat grammar) => grammar switch {
        MapFormat.Legacy => 0xEFU,
        MapFormat.Metadata => OrdinalFields ? 0xE7U : 0xE3U,
        _ => throw new ArgumentOutOfRangeException(nameof(grammar))
    };
}
