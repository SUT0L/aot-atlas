namespace Atlas;

public sealed partial class Metadata {
    // Values can complete several signature roots before a later value fails.
    // The same insertion journal covers roots and the enclosing read, including
    // aliases that reuse an earlier node without extending the signature graph.
    internal readonly struct SignatureOperation(Metadata owner) : IDisposable {
        private readonly SignatureBuilder.Checkpoint checkpoint = owner.SignatureBuilder.MarkAppend();
        private readonly int signatureChanges = owner.BeginSignatureOperation();
        private readonly int scopes = owner.state.ReferencedScopeOrder.Count;
        private readonly int methods = owner.Methods.Count;
        private readonly int fields = owner.Fields.Count;
        private readonly int handles = owner.Handles.Count;

        internal void Rollback() {
            owner.SignatureBuilder.RollbackAppend(checkpoint);
            owner.RemoveSignatureChanges(signatureChanges);
            RemoveAppended(owner.MethodIndex, methods);
            RemoveAppended(owner.FieldIndex, fields);

            owner.Methods.RemoveRange(methods, owner.Methods.Count - methods);
            owner.Fields.RemoveRange(fields, owner.Fields.Count - fields);
            owner.Handles.RemoveRange(handles, owner.Handles.Count - handles);

            for (int i = 0; i < owner.Methods.Count; ++i) {
                var method = owner.Methods[i];

                if (method.Signature >= checkpoint.Methods) {
                    method.Signature = 0;
                    owner.Methods[i] = method;
                }
            }

            var scopeOrder = owner.state.ReferencedScopeOrder;

            if (scopeOrder.Count != scopes) {
                var removedScopes = new HashSet<uint>();

                for (int i = scopes; i < scopeOrder.Count; ++i) {
                    uint key = scopeOrder[i];
                    owner.referencedScopes.Remove(key);
                    removedScopes.Add(key);
                }

                scopeOrder.RemoveRange(scopes, scopeOrder.Count - scopes);

                // Reference identities retain the scope offset. Keeping one
                // after its scope is removed would bypass scope decoding on
                // the next read and publish a signature without its assembly.
                int handleBits = owner.HandleBits;
                uint[] identities = owner.referenceNames
                    .Where(entry => removedScopes.Contains(entry.Value.Scope >> handleBits))
                    .Select(entry => entry.Key)
                    .ToArray();

                foreach (uint key in identities)
                    owner.referenceNames.Remove(key);
            }
        }

        public void Dispose() {
            System.Diagnostics.Debug.Assert(owner.signatureOperations > 0);

            if (--owner.signatureOperations == 0)
                owner.ClearSignatureChanges();
        }

        private static void RemoveAppended(Dictionary<uint, int> cache, int start) {
            uint[] added = cache.Where(entry => entry.Value >= start).Select(entry => entry.Key).ToArray();

            foreach (uint key in added)
                cache.Remove(key);
        }
    }

    private int BeginSignatureOperation() {
        ++signatureOperations;
        return addedSignatures.Count;
    }

    private void RemoveSignatureChanges(int start) {
        for (int i = start; i < addedSignatures.Count; ++i) {
            var added = addedSignatures[i];
            (added.Method ? methodSignatureIndex : signatureIndex).Remove(added.Value);
        }

        addedSignatures.RemoveRange(start, addedSignatures.Count - start);
    }

    private void ClearSignatureChanges() {
        addedSignatures.Clear();

        // Keep small root reads reusable without retaining a large failed
        // constant or attribute batch for the metadata owner's lifetime.
        if (addedSignatures.Capacity > 256)
            addedSignatures.Capacity = 256;
    }
}
