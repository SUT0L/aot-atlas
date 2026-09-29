using System.Runtime.InteropServices;

namespace Atlas;

public struct MethodIdentity {
    public uint MetadataOffset, NativeOffset;
    public int Signature;
    public string Name;
    public bool AsyncVariant;

    public static MethodIdentity Read(uint token, Metadata metadata, NativeLayout layout, MapFormat format, bool maskedAsync = false) {
        MethodIdentity identity = default;
        if (format == MapFormat.Legacy) {
            var native = layout.Method(token);
            identity.NativeOffset = token;
            identity.Name = native.Name;
            identity.Signature = native.Signature;
            return identity;
        }

        if (format != MapFormat.Metadata)
            throw new InvalidOperationException("Method identities require a resolved map format.");

        int offsetBits = 32 - metadata.HandleBits;
        uint offsetMask = (1U << offsetBits) - 1;
        if (maskedAsync) {
            if ((token & ~(offsetMask | 0x80000000U)) != 0)
                throw new InvalidDataException("Method token contains unknown flags.");

            identity.AsyncVariant = (token & 0x80000000) != 0;
        } else if ((token >> offsetBits) != 0x28) {
            throw new InvalidDataException("Method token is not a Method metadata handle.");
        }

        identity.MetadataOffset = token & offsetMask;
        if (identity.MetadataOffset == 0)
            throw new InvalidDataException("Method token is nil.");

        int index = metadata.ReadMethod(identity.MetadataOffset);
        ref var method = ref CollectionsMarshal.AsSpan(metadata.Methods)[index];
        if (method.Signature == 0)
            method.Signature = metadata.MethodSignature(method.SignatureOffset);

        identity.Name = method.Name;
        identity.Signature = method.Signature;
        return identity;
    }
}
