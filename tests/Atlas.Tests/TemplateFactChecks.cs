using Atlas;

internal static class TemplateFactChecks {
    internal static void Run() {
        // NativeLayout bags use ordinary NativeFormat integers for sizes and indices.
        var data = new byte[] { 0x88, 32, 0x8a, 48, 0x8c, 0, 0x8e, 64, 0x90, 2, 0x9c, 4, 0 };
        var facts = TemplateLayoutFacts.Read(data, 0, new ulong[] { 0x1000, 0x2000, 0x3000 });

        if (facts.NonGcStaticBytes != 16
            || facts.GcStaticBytes != 24
            || facts.ThreadStaticBytes != 32
            || facts.GcDescriptor != 0x1000
            || facts.ThreadDescriptor != 0x2000
            || facts.ClassConstructor != 0x3000) {
            throw new Exception("Template static facts mismatch.");
        }

        Reject(new byte[] { 0x88, 2, 0x88, 4, 0 }, new ulong[] { 0x1000 }); // Duplicate size
        Reject(new byte[] { 0x9c, 2, 0 }, new ulong[] { 0x1000 }); // Index beyond table
        Reject(new byte[] { 0x9c, 0, 0 }, new ulong[] { 0 }); // Null constructor
        Reject(new byte[] { 0x9c }, Array.Empty<ulong>()); // Truncated bag

        var unknown = TemplateLayoutFacts.Read(new byte[] { 2, 2, 0 }, 0, Array.Empty<ulong>());
        if (unknown.ClassConstructor != 0)
            throw new Exception("Unknown template field changed static facts.");
    }

    private static void Reject(byte[] data, ulong[] references) {
        try {
            TemplateLayoutFacts.Read(data, 0, references);
        } catch (InvalidDataException) {
            return;
        }

        throw new Exception("Malformed template bag was accepted.");
    }
}
