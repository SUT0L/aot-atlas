namespace Atlas;

public readonly struct SignatureDraftType {
    private readonly SignatureBuilder? owner;
    internal int Index { get; }

    internal SignatureDraftType(SignatureBuilder owner, int index) {
        this.owner = owner;
        Index = index;
    }

    internal int For(SignatureBuilder builder) {
        if (!ReferenceEquals(owner, builder))
            throw new ArgumentException("The signature belongs to a different builder.");

        return Index;
    }

    public SignatureType In(Signatures publication) {
        if (owner is null || !owner.Owns(publication) || (uint)Index >= (uint)publication.Nodes.Length)
            throw new ArgumentException("The publication does not contain this draft signature.", nameof(publication));

        return publication.Types[Index];
    }
}

public readonly struct SignatureDraftMethod {
    private readonly SignatureBuilder owner;
    internal int Index { get; }

    internal SignatureDraftMethod(SignatureBuilder owner, int index) {
        this.owner = owner;
        Index = index;
    }

    public SignatureMethod In(Signatures publication) {
        if (owner is null || !owner.Owns(publication) || (uint)Index >= (uint)publication.Methods.Length)
            throw new ArgumentException("The publication does not contain this draft method signature.", nameof(publication));

        return publication.MethodSignatures[Index];
    }
}

public sealed partial class SignatureBuilder {
    public SignatureDraftType Named(string name, uint metadataScope = 0) {
        ArgumentException.ThrowIfNullOrEmpty(name);

        return new(this, AddNode(new() {
            Kind = SignatureKind.Named,
            Name = name,
            MetadataScope = metadataScope
        }));
    }

    public SignatureDraftType RuntimeType(ulong address) {
        ArgumentOutOfRangeException.ThrowIfZero(address);

        return new(this, AddNode(new() { Kind = SignatureKind.RuntimeType, TypeAddress = address }));
    }

    public SignatureDraftType Variable(int position, bool method = false) {
        ArgumentOutOfRangeException.ThrowIfNegative(position);

        return new(this, AddNode(new() {
            Kind = method ? SignatureKind.MethodVariable : SignatureKind.TypeVariable,
            Value = position
        }));
    }

    public SignatureDraftType Pointer(SignatureDraftType element) => Compound(SignatureKind.Pointer, element);
    public SignatureDraftType ByReference(SignatureDraftType element) => Compound(SignatureKind.ByReference, element);
    public SignatureDraftType SzArray(SignatureDraftType element) => Compound(SignatureKind.SzArray, element);

    private SignatureDraftType Compound(SignatureKind kind, SignatureDraftType element) =>
        new(this, AddNode(new() { Kind = kind, Element = element.For(this) }));

    public SignatureDraftType Array(
        SignatureDraftType element,
        int rank,
        ReadOnlySpan<int> sizes = default,
        ReadOnlySpan<int> lowerBounds = default) {
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(rank);
        int child = element.For(this);
        ArgumentOutOfRangeException.ThrowIfGreaterThan(sizes.Length, rank);
        ArgumentOutOfRangeException.ThrowIfGreaterThan(lowerBounds.Length, rank);

        foreach (int size in sizes)
            ArgumentOutOfRangeException.ThrowIfNegative(size);

        ReserveConstruction(1, 0, checked(sizes.Length + lowerBounds.Length));
        var shape = AddValues(sizes);
        var bounds = AddValues(lowerBounds);

        return new(this, AddNode(new() {
            Kind = SignatureKind.Array,
            Element = child,
            Value = rank,
            Sizes = shape,
            LowerBounds = bounds
        }));
    }

    public SignatureDraftType FunctionPointer(
        SignatureDraftType returnType,
        ReadOnlySpan<SignatureDraftType> parameters = default,
        uint callingConvention = 0,
        bool nativeConvention = false,
        ReadOnlySpan<SignatureDraftType> varargs = default) {
        int result = returnType.For(this);
        ValidateArguments(parameters);
        ValidateArguments(varargs);
        ReserveConstruction(1, 0, checked(parameters.Length + varargs.Length));
        var fixedArguments = AddArguments(parameters);
        var variableArguments = AddArguments(varargs);

        return new(this, AddNode(new() {
            Kind = SignatureKind.FunctionPointer,
            Element = result,
            Value = unchecked((int)callingConvention),
            NativeConvention = nativeConvention,
            Arguments = fixedArguments,
            Varargs = variableArguments
        }));
    }

    public SignatureDraftType Modified(SignatureDraftType element, SignatureDraftType modifier, bool optional = false) =>
        new(this, AddNode(new() {
            Kind = SignatureKind.Modified,
            Element = element.For(this),
            Value = modifier.For(this),
            Optional = optional
        }));

    public SignatureDraftType Instantiate(SignatureDraftType definition, ReadOnlySpan<SignatureDraftType> arguments) {
        int element = definition.For(this);
        ValidateArguments(arguments);
        ReserveConstruction(1, 0, arguments.Length);
        var range = AddArguments(arguments);

        return new(this, AddNode(new() { Kind = SignatureKind.Instantiation, Element = element, Arguments = range }));
    }

    public SignatureDraftMethod Method(
        SignatureDraftType returnType,
        ReadOnlySpan<SignatureDraftType> parameters = default,
        uint callingConvention = 0,
        int genericParameterCount = 0,
        ReadOnlySpan<SignatureDraftType> varargs = default,
        bool nativeConvention = false) {
        ArgumentOutOfRangeException.ThrowIfNegative(genericParameterCount);
        int result = returnType.For(this);
        ValidateArguments(parameters);
        ValidateArguments(varargs);
        ReserveConstruction(0, 1, checked(parameters.Length + varargs.Length));
        var fixedArguments = AddArguments(parameters);
        var variableArguments = AddArguments(varargs);

        return new(this, AddMethod(new() {
            ReturnType = result,
            CallingConvention = callingConvention,
            GenericParameterCount = genericParameterCount,
            NativeConvention = nativeConvention,
            Parameters = fixedArguments,
            Varargs = variableArguments
        }));
    }

    private void ReserveConstruction(int nodeCount, int methodCount, int edgeCount) {
        nodes.EnsureCapacity(checked(nodes.Count + nodeCount));
        methods.EnsureCapacity(checked(methods.Count + methodCount));
        edges.EnsureCapacity(checked(edges.Count + edgeCount));
    }

    private IndexRange AddArguments(ReadOnlySpan<SignatureDraftType> arguments) {
        var range = ReserveEdges(arguments.Length);

        for (int i = 0; i < arguments.Length; ++i)
            SetEdge(range.Start + i, arguments[i].Index);

        return range;
    }

    private void ValidateArguments(ReadOnlySpan<SignatureDraftType> arguments) {
        foreach (var argument in arguments)
            argument.For(this);
    }

    private IndexRange AddValues(ReadOnlySpan<int> values) {
        var range = ReserveEdges(values.Length);

        for (int i = 0; i < values.Length; ++i)
            SetEdge(range.Start + i, values[i]);

        return range;
    }
}
