using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text;

namespace Atlas;

// Parser storage is private. Borrowed spans expire on mutation; published graphs do not.
public sealed partial class SignatureBuilder {
    private readonly SignatureHistory history;
    private readonly List<SignatureNode> nodes;
    private readonly List<int> edges;
    private readonly List<MethodSignature> methods;

    private Signatures? published;
    private bool reading;
    private bool hasAbbreviatedReferences;

    public SignatureBuilder() : this(32768, 65536, 16384) {
    }

    internal SignatureBuilder(int nodeCapacity, int edgeCapacity, int methodCapacity) {
        history = new();
        nodes = new(nodeCapacity) { default };
        edges = new(edgeCapacity);
        methods = new(methodCapacity) { default };
    }

    private SignatureBuilder(SignatureBuilder source, bool newOrigin) {
        if (source.reading)
            throw new InvalidOperationException("A signature graph cannot be forked during a record read.");

        history = newOrigin ? new() : source.history;
        nodes = new(source.nodes);
        edges = new(source.edges);
        methods = new(source.methods);
        hasAbbreviatedReferences = source.HasAbbreviatedReferences;
        published = newOrigin ? null : source.published;
    }

    internal SignatureBuilder Fork(bool newOrigin) => new(this, newOrigin);

    public bool HasAbbreviatedReferences => hasAbbreviatedReferences
        || published is { HasAbbreviatedReferences: true };
    internal bool Owns(Signatures graph) => graph.IsOwnedBy(history);
    internal SignatureHistory Origin => history;

    internal ReadOnlySpan<SignatureNode> Nodes => CollectionsMarshal.AsSpan(nodes);
    internal ReadOnlySpan<int> Edges => CollectionsMarshal.AsSpan(edges);
    internal ReadOnlySpan<MethodSignature> Methods => CollectionsMarshal.AsSpan(methods);

    internal int AddNode(SignatureNode node) {
        int index = nodes.Count;
        nodes.Add(node);
        InvalidatePublication();

        return index;
    }

    internal int AddMethod(MethodSignature method) {
        int index = methods.Count;
        methods.Add(method);
        InvalidatePublication();

        return index;
    }

    internal void AddEdge(int signature) {
        edges.Add(signature);
        InvalidatePublication();
    }

    internal void SetNode(int index, SignatureNode node) {
        nodes[index] = node;
        InvalidatePublication();
    }

    internal void SetMethod(int index, MethodSignature method) {
        methods[index] = method;
        InvalidatePublication();
    }

    internal void SetEdge(int index, int signature) {
        edges[index] = signature;
        InvalidatePublication();
    }

    internal IndexRange ReserveEdges(int count) {
        ArgumentOutOfRangeException.ThrowIfNegative(count);

        int start = edges.Count;
        CollectionsMarshal.SetCount(edges, checked(start + count));
        InvalidatePublication();

        return new(start, count);
    }

    // Publication copies the live prefix once. Further parsing cannot change a binding's graph.
    public Signatures Publish() {
        if (reading)
            throw new InvalidOperationException("A signature read must complete before its graph is published.");

        return published ??= new(history, nodes.ToArray(), edges.ToArray(), methods.ToArray(),
            hasAbbreviatedReferences);
    }

    private void InvalidatePublication() {
        hasAbbreviatedReferences = HasAbbreviatedReferences;
        published = null;
    }

    internal readonly record struct Checkpoint(
        SignatureBuilder Owner,
        int Nodes,
        int Edges,
        int Methods,
        Signatures? Published,
        bool HasAbbreviatedReferences);

    internal Checkpoint BeginRead() {
        if (reading)
            throw new InvalidOperationException("Signature parser roots cannot overlap.");

        reading = true;

        return new(this, nodes.Count, edges.Count, methods.Count, published, hasAbbreviatedReferences);
    }

    internal Checkpoint MarkAppend() {
        if (reading)
            throw new InvalidOperationException("A compound read cannot begin inside a signature root.");

        return new(this, nodes.Count, edges.Count, methods.Count, published, hasAbbreviatedReferences);
    }

    internal void RollbackAppend(Checkpoint checkpoint) {
        Debug.Assert(!reading && ReferenceEquals(checkpoint.Owner, this));

        Restore(checkpoint);
    }

    internal void CompleteRead(Checkpoint checkpoint) {
        Debug.Assert(reading && ReferenceEquals(checkpoint.Owner, this));

        reading = false;
    }

    internal void RollbackRead(Checkpoint checkpoint) {
        Debug.Assert(reading && ReferenceEquals(checkpoint.Owner, this));

        Restore(checkpoint);
        reading = false;
    }

    private void Restore(Checkpoint checkpoint) {
        nodes.RemoveRange(checkpoint.Nodes, nodes.Count - checkpoint.Nodes);
        edges.RemoveRange(checkpoint.Edges, edges.Count - checkpoint.Edges);
        methods.RemoveRange(checkpoint.Methods, methods.Count - checkpoint.Methods);

        published = checkpoint.Published;
        hasAbbreviatedReferences = checkpoint.HasAbbreviatedReferences;
    }

    // Metadata values need a display while parsing; this borrows storage without publication.
    internal string RenderType(
        int index,
        ReadOnlySpan<string> typeArguments = default,
        ReadOnlySpan<string> methodArguments = default) {
        var builder = new StringBuilder();

        if (!SignatureRendering.AppendType(builder, index, Nodes, Edges, Methods, typeArguments, methodArguments))
            hasAbbreviatedReferences = true;

        return builder.ToString();
    }

    internal string RenderMethod(
        string name,
        int index,
        ReadOnlySpan<string> typeArguments = default,
        ReadOnlySpan<string> methodArguments = default) {
        var builder = new StringBuilder(name);

        if (!SignatureRendering.AppendMethod(builder, index, Nodes, Edges, Methods, typeArguments, methodArguments))
            hasAbbreviatedReferences = true;

        return builder.ToString();
    }
}
