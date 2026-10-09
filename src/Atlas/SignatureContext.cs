namespace Atlas;

public enum SignatureArgumentKind : byte {
    Unresolved,
    RuntimeType,
    TypeSignature,
    ParameterName
}

// Identity and its display travel together; equal names need not name equal types.
public readonly struct SignatureArgument {
    public SignatureArgumentKind Kind { get; }
    public ulong TypeAddress { get; }
    internal int Signature { get; }
    public SignatureType Type { get; }
    public string Display { get; }

    private SignatureArgument(
        SignatureArgumentKind kind,
        string display,
        ulong address = 0,
        int signature = 0,
        SignatureType type = default) {
        ArgumentNullException.ThrowIfNull(display);

        Kind = kind;
        Display = display;
        TypeAddress = address;
        Signature = signature;
        Type = type;
    }

    public static SignatureArgument RuntimeType(ulong address, string display) {
        ArgumentOutOfRangeException.ThrowIfZero(address);

        return new(SignatureArgumentKind.RuntimeType, display, address);
    }

    // The referenced declaration is rendered without substitutions, as in RenderType(signature).
    public static SignatureArgument TypeSignature(SignatureType signature, string display) {
        if (signature.IsEmpty)
            return new(SignatureArgumentKind.Unresolved, display);

        return new(SignatureArgumentKind.TypeSignature, display, signature: signature.Index, type: signature);
    }

    internal static SignatureArgument TypeSignature(int signature, string display) {
        ArgumentOutOfRangeException.ThrowIfNegative(signature);

        if (signature == 0)
            return new(SignatureArgumentKind.Unresolved, display);

        return new(SignatureArgumentKind.TypeSignature, display, signature: signature);
    }

    public static SignatureArgument ParameterName(string name) => new(
        string.IsNullOrEmpty(name) ? SignatureArgumentKind.Unresolved : SignatureArgumentKind.ParameterName,
        name);
}

// Borrowed arguments: a MethodText context remains valid until its next Render call.
public readonly ref struct SignatureContext(
    ReadOnlySpan<SignatureArgument> typeArguments,
    ReadOnlySpan<SignatureArgument> methodArguments = default) {
    public ReadOnlySpan<SignatureArgument> TypeArguments { get; } = typeArguments;
    public ReadOnlySpan<SignatureArgument> MethodArguments { get; } = methodArguments;
}
