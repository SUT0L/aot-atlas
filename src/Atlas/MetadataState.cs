namespace Atlas;

public sealed partial class Metadata {
    // One owner contains both definition storage and the caches that refer to it.
    // A failed bulk read never installs its private working state.
    private sealed class State {
        internal readonly List<MetadataScope> Scopes;
        internal readonly List<MetadataType> Types;
        internal readonly List<MetadataMethod> Methods;
        internal readonly List<MetadataField> Fields;
        internal readonly List<MetadataForwarder> Forwarders;
        internal readonly List<MetadataAttribute> Attributes;
        internal readonly List<uint> Handles;

        internal readonly Dictionary<uint, int> TypeIndex;
        internal readonly Dictionary<uint, int> MethodIndex;
        internal readonly Dictionary<uint, int> FieldIndex;
        internal readonly Dictionary<uint, int> ScopeIndex;
        internal readonly Dictionary<uint, string> Strings;
        internal readonly Dictionary<uint, (uint Scope, string Name)> Namespaces;

        internal readonly Dictionary<uint, int> SignatureIndex;
        internal readonly Dictionary<uint, int> MethodSignatureIndex;
        internal readonly Dictionary<uint, (string Name, uint Scope)> ReferenceNames;
        internal readonly Dictionary<uint, string> OtherDefinitionNames;
        internal readonly Dictionary<uint, MetadataScopeReference> ReferencedScopes;
        internal readonly List<uint> ReferencedScopeOrder;

        internal readonly SignatureBuilder Signatures;

        internal State() {
            Scopes = new();
            Types = new();
            Methods = new();
            Fields = new();
            Forwarders = new();
            Attributes = new();
            Handles = new();

            TypeIndex = new();
            MethodIndex = new();
            FieldIndex = new();
            ScopeIndex = new();
            Strings = new();
            Namespaces = new();

            SignatureIndex = new();
            MethodSignatureIndex = new();
            ReferenceNames = new();
            OtherDefinitionNames = new();
            ReferencedScopes = new();
            ReferencedScopeOrder = new();

            Signatures = new(1, 0, 1);
        }

        internal State(State source, bool newOrigin) {
            Scopes = new(source.Scopes);
            Types = new(source.Types);
            Methods = new(source.Methods);
            Fields = new(source.Fields);
            Forwarders = new(source.Forwarders);
            Attributes = new(source.Attributes);
            Handles = new(source.Handles);

            TypeIndex = new(source.TypeIndex);
            MethodIndex = new(source.MethodIndex);
            FieldIndex = new(source.FieldIndex);
            ScopeIndex = new(source.ScopeIndex);
            Strings = new(source.Strings);
            Namespaces = new(source.Namespaces);

            SignatureIndex = new(source.SignatureIndex);
            MethodSignatureIndex = new(source.MethodSignatureIndex);
            ReferenceNames = new(source.ReferenceNames);
            OtherDefinitionNames = new(source.OtherDefinitionNames);
            ReferencedScopes = new(source.ReferencedScopes);
            ReferencedScopeOrder = new(source.ReferencedScopeOrder);

            Signatures = source.Signatures.Fork(newOrigin);
        }
    }

    private State state;

    private Metadata(Metadata source, bool newOrigin) {
        if (source.readingSignatures || source.activeNames.Count != 0)
            throw new InvalidOperationException("Metadata cannot be forked during a record read.");

        Data = source.Data;
        HandleBits = source.HandleBits;
        LegacyConstants = source.LegacyConstants;
        state = new(source.state, newOrigin);
    }

    internal Metadata Fork() => new(this, newOrigin: true);

    internal Metadata WorkingCopy() => new(this, newOrigin: false);

    internal void Adopt(Metadata working) {
        if (!Data.Equals(working.Data)
            || !ReferenceEquals(SignatureBuilder.Origin, working.SignatureBuilder.Origin))
            throw new ArgumentException("Metadata working state belongs to different input.", nameof(working));

        state = working.state;
    }
}
