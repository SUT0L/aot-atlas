using Atlas;

internal static class NativeReaderSourceChecks {
    internal static void Run() {
        byte[] storage = [0x2A, 0x2A, 0xAA, 0x2A]; // native builtins: System.Void, System.Byte
        var source = storage.AsMemory(1, 2);
        var signatures = new SignatureBuilder();
        var layout = new NativeLayout(source, [], signatures, takeOwnership: true);

        // A foreign reader must reject before its first parse or a cached lookup.
        Reject(layout, signatures, new NativeReader(new byte[] { 0xAA, 0x2A }));

        var matching = new NativeReader(storage.AsSpan(1, 2));
        int first = layout.TypeSignature(ref matching);
        int second = layout.TypeSignature(ref matching);

        Assert(first == 1 && second == 2 && matching.Position == 2);
        Assert(signatures.RenderType(first) == "System.Void" && signatures.RenderType(second) == "System.Byte");

        Reject(layout, signatures, new NativeReader(new byte[] { 0x2A, 0xAA })); // equal bytes, separate storage
        Reject(layout, signatures, new NativeReader(new byte[] { 0xAA, 0x2A }, 1));
        Reject(layout, signatures, new NativeReader(storage.AsSpan(0, 2))); // same extent, shifted coordinates
        Reject(layout, signatures, new NativeReader(storage.AsSpan(2, 2)));

        // Native offsets address the complete blob. A shorter prefix or suffix is
        // deliberately a different source, even when its bytes overlap the owner.
        Reject(layout, signatures, new NativeReader(storage.AsSpan(1, 1)));
        Reject(layout, signatures, new NativeReader(storage.AsSpan(2, 1)));
        Reject(layout, signatures, new NativeReader(storage));
        Reject(layout, signatures, new NativeReader(ReadOnlySpan<byte>.Empty));

        matching.Position = 0;
        Assert(layout.TypeSignature(ref matching) == first && matching.Position == 1);
        Assert(layout.TypeSignature(ref matching) == second && matching.Position == 2);
        Assert(signatures.Nodes.Length == 3 && signatures.Methods.Length == 1 && signatures.Edges.Length == 0);

        Console.WriteLine("Native reader source: distinct storage, altered origin/extent, cache hits, unchanged rejection state and matching-reader progress passed.");
    }

    private static void Reject(NativeLayout layout, SignatureBuilder signatures, NativeReader reader) {
        int position = reader.Position;
        var nodes = signatures.Nodes.ToArray();
        var methods = signatures.Methods.ToArray();
        var edges = signatures.Edges.ToArray();
        var externalTypes = layout.ExternalTypes.ToArray();

        bool rejected = false;

        try {
            layout.TypeSignature(ref reader);
        } catch (ArgumentException error) {
            rejected = error.ParamName == "reader";
        }

        Assert(rejected && reader.Position == position);
        Assert(signatures.Nodes.SequenceEqual(nodes)
            && signatures.Methods.SequenceEqual(methods)
            && signatures.Edges.SequenceEqual(edges)
            && layout.ExternalTypes.SequenceEqual(externalTypes));
    }

    private static void Assert(bool condition) {
        if (!condition)
            throw new Exception("Native reader source assertion failed.");
    }
}
