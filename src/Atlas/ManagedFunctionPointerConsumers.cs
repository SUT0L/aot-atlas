using System.Security.Cryptography;

namespace Atlas;

public readonly struct DelegateConsumerResult {
    private readonly FunctionPointerConsumer[]? consumers;
    public ReadOnlySpan<FunctionPointerConsumer> Consumers => consumers;
    public string Status { get; }
    public string? Error { get; }

    internal DelegateConsumerResult(FunctionPointerConsumer[] consumers, string status, string? error) {
        this.consumers = consumers;
        Status = status;
        Error = error;
    }

    public static DelegateConsumerResult Unavailable(string? error) => new([], "unavailable", error);
}

public static class ManagedFunctionPointerConsumers {
    private readonly record struct ScopeIdentity(
        ushort Major,
        ushort Minor,
        ushort Build,
        ushort Revision,
        string Token,
        string Culture);

    public static ReadOnlySpan<FunctionPointerConsumer> ReadConsumers(
        Metadata metadata,
        TraceMaps traces,
        Signatures signatures,
        CancellationToken cancellationToken = default) =>
        Read(metadata, traces, signatures, cancellationToken);

    public static DelegateConsumerResult ReadResult(
        Metadata metadata,
        TraceMaps traces,
        Signatures signatures,
        CancellationToken cancellationToken = default) {
        try {
            var consumers = Read(metadata, traces, signatures, cancellationToken);
            return new(consumers, traces.MethodEntries.IsEmpty ? "unavailable" : "complete", null);
        } catch (Exception error) when (error is InvalidDataException or NotSupportedException or OverflowException) {
            return DelegateConsumerResult.Unavailable(error.Message);
        }
    }

    internal static FunctionPointerConsumer[] Read(
        Metadata metadata,
        TraceMaps traces,
        Signatures signatures,
        CancellationToken cancellationToken = default) {
        cancellationToken.ThrowIfCancellationRequested();
        if (!metadata.PublishedSignatures.SharesOrigin(signatures))
            throw new InvalidOperationException("Delegate consumer signatures belong to a different metadata graph.");

        traces.ValidateSignatures(signatures, cancellationToken);

        var targets = new HashSet<ulong>();
        var conflicts = new HashSet<ulong>();
        var coreScopes = new Dictionary<uint, ScopeIdentity>();

        foreach (var scope in metadata.Scopes) {
            cancellationToken.ThrowIfCancellationRequested();

            if (scope.Name == "System.Private.CoreLib")
                coreScopes.Add(
                    (scope.Offset << metadata.HandleBits) | 0x38,
                    new ScopeIdentity(
                        scope.Major, scope.Minor, scope.Build, scope.Revision,
                        Token(scope.PublicKey.Span, (scope.Flags & 1) != 0),
                        scope.Culture.ToUpperInvariant()));
        }

        foreach (var scope in metadata.ReferencedScopes) {
            cancellationToken.ThrowIfCancellationRequested();

            if (scope.Name == "System.Private.CoreLib")
                coreScopes.Add(
                    (scope.Offset << metadata.HandleBits) | 0x39,
                    new ScopeIdentity(
                        scope.Major, scope.Minor, scope.Build, scope.Revision,
                        Token(scope.PublicKeyOrToken.Span, (scope.Flags & 1) != 0),
                        scope.Culture.ToUpperInvariant()));
        }

        foreach (var trace in traces.Methods) {
            cancellationToken.ThrowIfCancellationRequested();

            int count = trace.Name switch {
                "InitializeOpenStaticThunk" or "InitializeClosedStaticThunk" => 3,
                "InitializeClosedInstanceSlow" or "InitializeClosedInstanceWithoutNullCheck" => 2,
                _ => 0
            };

            if (count == 0 || trace.Signature == 0 || trace.DeclaringType == 0)
                continue;

            var declaring = signatures.Nodes[trace.DeclaringType];
            if (declaring.Kind != SignatureKind.Named
                || declaring.Name != "System.Delegate"
                || !coreScopes.TryGetValue(declaring.MetadataScope, out var ownerScope))
                continue;

            var signature = signatures.Methods[trace.Signature];
            bool valid = !signature.NativeConvention
                && signature.CallingConvention == 0x20
                && signature.GenericParameterCount == 0
                && signature.Parameters.Count == count
                && signature.Varargs.Count == 0
                && Named(signatures, coreScopes, ownerScope, signature.ReturnType, "System.Void")
                && Named(
                    signatures, coreScopes, ownerScope,
                    signatures.Edges[signature.Parameters.Start], "System.Object")
                && Named(
                    signatures, coreScopes, ownerScope,
                    signatures.Edges[signature.Parameters.Start + 1], "System.IntPtr")
                && (count == 2 || Named(
                    signatures, coreScopes, ownerScope,
                    signatures.Edges[signature.Parameters.Start + 2], "System.IntPtr"));

            if (valid)
                targets.Add(trace.Entrypoint);
            else
                conflicts.Add(trace.Entrypoint);
        }

        foreach (ulong conflict in conflicts) {
            cancellationToken.ThrowIfCancellationRequested();
            targets.Remove(conflict);
        }

        var result = new FunctionPointerConsumer[targets.Count];
        int position = 0;

        foreach (ulong target in targets) {
            cancellationToken.ThrowIfCancellationRequested();
            result[position++] = new(target, 8);
        }

        cancellationToken.ThrowIfCancellationRequested();
        return result;
    }

    private static bool Named(
        Signatures signatures,
        Dictionary<uint, ScopeIdentity> scopes,
        ScopeIdentity owner,
        int index,
        string name) {
        var type = signatures.Nodes[index];

        return type.Kind == SignatureKind.Named
            && type.Name == name
            && scopes.TryGetValue(type.MetadataScope, out var scope)
            && scope == owner;
    }

    private static string Token(ReadOnlySpan<byte> key, bool fullKey) {
        if (!fullKey || key.IsEmpty)
            return Convert.ToHexString(key);

        Span<byte> hash = stackalloc byte[20];
        SHA1.HashData(key, hash);
        hash[12..].Reverse();

        return Convert.ToHexString(hash[12..]);
    }
}
