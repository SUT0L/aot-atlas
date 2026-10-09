namespace Atlas;

public sealed class ReflectionMapBuilder {
    private readonly Signatures publication;
    private ReflectionMaps? draft = new();

    public ReflectionMapBuilder(Signatures publication) {
        ArgumentNullException.ThrowIfNull(publication);
        this.publication = publication;
        draft.SetSignatureOrigin(publication);
    }

    public void Type(ulong methodTable, SignatureType signature, string? name = null) {
        ArgumentOutOfRangeException.ThrowIfZero(methodTable);

        if (!ReferenceEquals(signature.Publication, publication))
            throw new ArgumentException("The mapped type belongs to a different signature publication.", nameof(signature));

        if (signature.Kind != SignatureKind.Named)
            throw new ArgumentException("A metadata type map requires a named signature.", nameof(signature));

        var result = draft ?? throw new InvalidOperationException("The reflection maps have already been published.");
        result.Types.Add(new() {
            MethodTable = methodTable,
            Signature = signature.Index,
            Name = name ?? signature.Name!
        });
    }

    public ReflectionMaps Publish() {
        var result = draft ?? throw new InvalidOperationException("The reflection maps have already been published.");
        draft = null;

        return result;
    }

    public void Method(InvokeMapEntry entry, SignatureMethod signature, ReadOnlySpan<ulong> arguments = default) {
        if (signature.IsEmpty)
            throw new ArgumentException("The mapped method signature is empty.", nameof(signature));

        if (!ReferenceEquals(signature.Publication, publication))
            throw new ArgumentException("The mapped method belongs to a different signature publication.", nameof(signature));

        ArgumentException.ThrowIfNullOrEmpty(entry.Name);
        ArgumentOutOfRangeException.ThrowIfZero(entry.DeclaringType);

        foreach (ulong argument in arguments)
            ArgumentOutOfRangeException.ThrowIfZero(argument);

        var result = draft ?? throw new InvalidOperationException("The reflection maps have already been published.");
        result.Methods.EnsureCapacity(checked(result.Methods.Count + 1));
        result.GenericArguments.EnsureCapacity(checked(result.GenericArguments.Count + arguments.Length));
        entry.Signature = signature.Index;
        entry.GenericArguments = new(result.GenericArguments.Count, arguments.Length);

        foreach (ulong argument in arguments)
            result.GenericArguments.Add(argument);

        result.Methods.Add(entry);
    }

    public void Field(FieldMapEntry entry, SignatureType signature) {
        if (signature.IsEmpty)
            throw new ArgumentException("The mapped field signature is empty.", nameof(signature));

        if (!ReferenceEquals(signature.Publication, publication))
            throw new ArgumentException("The mapped field belongs to a different signature publication.", nameof(signature));

        ArgumentException.ThrowIfNullOrEmpty(entry.Name);
        ArgumentOutOfRangeException.ThrowIfZero(entry.DeclaringType);
        var result = draft ?? throw new InvalidOperationException("The reflection maps have already been published.");
        entry.Signature = signature.Index;
        result.Fields.Add(entry);
    }
}
