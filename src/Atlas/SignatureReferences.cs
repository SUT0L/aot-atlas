using System.Text;

namespace Atlas;

public readonly struct SignatureType {
    private readonly Signatures? publication;
    internal int Index { get; }
    internal Signatures Publication => publication
        ?? throw new InvalidOperationException("The signature reference is empty.");

    internal SignatureType(Signatures publication, int index) {
        this.publication = publication;
        Index = index;
    }

    public bool IsEmpty => publication is null || Index == 0;
    public SignatureKind Kind => publication is null ? SignatureKind.Unknown : publication.Nodes[Index].Kind;
    public string? Name => Publication.Nodes[Index].Name;
    public ulong TypeAddress => Publication.Nodes[Index].TypeAddress;
    public uint MetadataScope => Publication.Nodes[Index].MetadataScope;
    public int VariablePosition {
        get {
            if (Kind is not (SignatureKind.TypeVariable or SignatureKind.MethodVariable))
                throw new InvalidOperationException("The signature is not a generic variable.");

            return Publication.Nodes[Index].Value;
        }
    }

    public int ArrayRank => Kind switch {
        SignatureKind.SzArray => 1,
        SignatureKind.Array => Publication.Nodes[Index].Value,
        _ => throw new InvalidOperationException("The signature is not an array.")
    };

    public uint FunctionPointerConvention => Kind == SignatureKind.FunctionPointer
        ? (uint)Publication.Nodes[Index].Value
        : throw new InvalidOperationException("The signature is not a function pointer.");
    public bool Optional => Kind == SignatureKind.Modified
        ? Publication.Nodes[Index].Optional
        : throw new InvalidOperationException("The signature is not modified.");
    public bool NativeConvention => Kind == SignatureKind.FunctionPointer
        ? Publication.Nodes[Index].NativeConvention
        : throw new InvalidOperationException("The signature is not a function pointer.");
    public SignatureType Element => Kind is SignatureKind.Array or SignatureKind.SzArray
        or SignatureKind.Pointer or SignatureKind.ByReference or SignatureKind.Instantiation
        or SignatureKind.FunctionPointer or SignatureKind.Modified
        ? Publication.Types[Publication.Nodes[Index].Element]
        : default;
    public SignatureType Modifier => Kind == SignatureKind.Modified
        ? Publication.Types[Publication.Nodes[Index].Value]
        : default;
    public SignatureTypes Arguments => Kind is SignatureKind.Instantiation or SignatureKind.FunctionPointer
        ? new(Publication, Publication.Nodes[Index].Arguments)
        : default;
    public SignatureTypes Varargs => Kind == SignatureKind.FunctionPointer
        ? new(Publication, Publication.Nodes[Index].Varargs)
        : default;
    public ReadOnlySpan<int> ArraySizes => Kind == SignatureKind.Array
        ? Publication.Edges.Slice(Publication.Nodes[Index].Sizes.Start, Publication.Nodes[Index].Sizes.Count)
        : [];
    public ReadOnlySpan<int> ArrayLowerBounds => Kind == SignatureKind.Array
        ? Publication.Edges.Slice(Publication.Nodes[Index].LowerBounds.Start, Publication.Nodes[Index].LowerBounds.Count)
        : [];

    public string Render(
        ReadOnlySpan<string> typeArguments = default,
        ReadOnlySpan<string> methodArguments = default) =>
        Publication.RenderType(Index, typeArguments, methodArguments);

    public bool Append(
        StringBuilder target,
        ReadOnlySpan<string> typeArguments = default,
        ReadOnlySpan<string> methodArguments = default) =>
        Publication.AppendTypeWithStatus(target, Index, typeArguments, methodArguments);
}

public readonly struct SignatureMethod {
    private readonly Signatures? publication;
    internal int Index { get; }
    internal Signatures Publication => publication
        ?? throw new InvalidOperationException("The method signature reference is empty.");

    internal SignatureMethod(Signatures publication, int index) {
        this.publication = publication;
        Index = index;
    }

    public bool IsEmpty => publication is null || Index == 0;
    public uint Offset => Publication.Methods[Index].Offset;
    public uint CallingConvention => Publication.Methods[Index].CallingConvention;
    public int GenericParameterCount => Publication.Methods[Index].GenericParameterCount;
    public bool NativeConvention => Publication.Methods[Index].NativeConvention;
    public SignatureType ReturnType => Publication.Types[Publication.Methods[Index].ReturnType];
    public SignatureTypes Parameters => new(Publication, Publication.Methods[Index].Parameters);
    public SignatureTypes Varargs => new(Publication, Publication.Methods[Index].Varargs);

    public string Render(
        string name,
        ReadOnlySpan<string> typeArguments = default,
        ReadOnlySpan<string> methodArguments = default) =>
        Publication.RenderMethod(name, Index, typeArguments, methodArguments);

    public bool Append(
        StringBuilder target,
        ReadOnlySpan<string> typeArguments = default,
        ReadOnlySpan<string> methodArguments = default) =>
        Publication.AppendMethodWithStatus(target, Index, typeArguments, methodArguments);
}

public readonly struct SignatureTypes {
    private readonly Signatures publication;
    private readonly IndexRange range;
    private readonly bool edges;

    internal SignatureTypes(Signatures publication) {
        this.publication = publication;
        range = new(0, publication.Nodes.Length);
        edges = false;
    }

    internal SignatureTypes(Signatures publication, IndexRange range) {
        this.publication = publication;
        this.range = range;
        edges = true;
    }

    public int Count => range.Count;
    public SignatureType this[int position] {
        get {
            ArgumentOutOfRangeException.ThrowIfNegative(position);
            ArgumentOutOfRangeException.ThrowIfGreaterThanOrEqual(position, range.Count);

            int index = range.Start + position;
            return new(publication, edges ? publication.Edges[index] : index);
        }
    }

    public Enumerator GetEnumerator() => new(this);

    public struct Enumerator {
        private readonly SignatureTypes values;
        private int position;

        internal Enumerator(SignatureTypes values) {
            this.values = values;
            position = -1;
        }

        public bool MoveNext() => ++position < values.Count;
        public SignatureType Current => values[position];
    }
}

public readonly struct SignatureMethods {
    private readonly Signatures? publication;
    internal SignatureMethods(Signatures publication) => this.publication = publication;
    public int Count => publication?.Methods.Length ?? 0;

    public SignatureMethod this[int position] {
        get {
            ArgumentOutOfRangeException.ThrowIfNegative(position);
            ArgumentOutOfRangeException.ThrowIfGreaterThanOrEqual(position, Count);

            return new(publication!, position);
        }
    }
}
