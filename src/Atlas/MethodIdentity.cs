namespace Atlas;

public struct MethodIdentity {
    public uint MetadataOffset;
    public uint NativeOffset;

    internal int Signature;
    public string Name;
    public bool AsyncVariant;
    public bool ReturnDroppingAsyncThunk;
    public MetadataFactStatus NameStatus;
    public MetadataFactStatus SignatureStatus;
    public readonly MetadataFactStatus MetadataStatus => NameStatus | SignatureStatus;

    internal static MethodIdentity Read(
        uint token,
        MetadataBuilder metadata,
        NativeLayout layout,
        MapFormat format,
        bool maskedAsync = false,
        bool returnDroppingAsyncThunks = false) {
        ReflectionMaps.RequireGrammar(format);

        MethodIdentity identity = new() { Name = "" };

        if (format == MapFormat.Legacy) {
            var native = layout.Method(token);
            identity.NativeOffset = token;
            identity.Name = native.Name;
            identity.Signature = native.Signature;

            return identity;
        }

        int offsetBits = 32 - metadata.HandleBits;
        uint offsetMask = (1U << offsetBits) - 1;
        if (maskedAsync) {
            uint allowedFlags = returnDroppingAsyncThunks ? 0xC0000000U : 0x80000000U;
            if ((token & ~(offsetMask | allowedFlags)) != 0)
                throw new InvalidDataException("Method token contains unknown flags.");

            identity.AsyncVariant = (token & 0x80000000) != 0;
            identity.ReturnDroppingAsyncThunk = (token & 0x40000000) != 0;
            if (identity.AsyncVariant && identity.ReturnDroppingAsyncThunk)
                throw new InvalidDataException("Method token selects two async variants.");
        } else if ((token >> offsetBits) != 0x28) {
            throw new InvalidDataException("Method token is not a Method metadata handle.");
        }

        identity.MetadataOffset = token & offsetMask;
        if (identity.MetadataOffset == 0)
            throw new InvalidDataException("Method token is nil.");

        var id = new MetadataRecordId(MetadataRecordKind.Method, identity.MetadataOffset);
        metadata.AddRoot(id);
        uint raw = metadata.Encoding.EncodeHandle(id);

        try {
            var name = metadata.RecordField(id, MetadataFieldName.Name).Reference;
            identity.NameStatus = name.Status;
            if (!name.IsAvailable || name.Value.IsNil) {
                identity.NameStatus |= MetadataFactStatus.Unresolved;
                throw new InvalidDataException($"Method name reference is unavailable ({identity.NameStatus}).");
            }
            var text = metadata.RecordName(new(name.Value.Offset));
            identity.NameStatus |= text.Status;
            if (!text.IsAvailable) {
                throw new InvalidDataException($"Method name is unavailable ({text.Status}).");
            }
            identity.Name = metadata.String(name.Value.Offset);
            if (identity.Name.Length == 0) {
                identity.NameStatus |= MetadataFactStatus.InvalidName;
                throw new InvalidDataException("Method has no name.");
            }
        } catch (Exception error) when (error is InvalidDataException or OverflowException or NotSupportedException) {
            identity.NameStatus |= MetadataFactStatus.Unresolved;
            metadata.RecordFailure(raw, "method identity name", error);
        }

        uint signatureHandle = raw;
        try {
            if (metadata.MethodIndex.TryGetValue(identity.MetadataOffset, out int index)
                && metadata.Methods[index].Signature != 0) {
                identity.Signature = metadata.Methods[index].Signature;
            } else {
                var signature = metadata.RecordField(id, MetadataFieldName.Signature).Reference;
                identity.SignatureStatus = signature.Status;
                if (!signature.IsAvailable || signature.Value.IsNil) {
                    identity.SignatureStatus |= MetadataFactStatus.Unresolved;
                    throw new InvalidDataException($"Method signature reference is unavailable ({identity.SignatureStatus}).");
                }
                signatureHandle = metadata.Encoding.EncodeHandle(signature.Value);
                if (!metadata.TryMethodSignature(signature.Value.Offset, out identity.Signature)) {
                    identity.SignatureStatus |= MetadataFactStatus.Unresolved;
                }
            }
        } catch (Exception error) when (error is InvalidDataException or OverflowException or NotSupportedException) {
            identity.SignatureStatus |= MetadataFactStatus.Unresolved;
            metadata.RecordFailure(signatureHandle, "method identity signature", error);
        }

        return identity;
    }
}
