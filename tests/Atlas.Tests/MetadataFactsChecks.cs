using System.Buffers.Binary;
using System.Text;
using Atlas;

internal static class MetadataFactsChecks {
    internal static void Run() {
        Check(System.Runtime.CompilerServices.Unsafe.SizeOf<FactCell>() == 24, "Owned fact cell stride.");
        NamedQueriesPreserveIndependentFacts();
        OwnershipNormalizesAcrossEncodings();
        ReferenceOwnershipNormalizesAcrossEncodings();
        DamagedEnclosingOwnerPreservesNamespace();
        OldConstantKindsRetainSourceIdentity();
        InvalidHandleEncodingIsExternalData();
        CollectionPrefixSurvivesDamage();
        ResourceLimitsRemainQueryable();
        CancellationStopsConstruction();
        NegativeArityRetainsRawBits();
        DamagedStringPrefixHasNoInventedPayload();
        InvalidRootHasNoSourceRange();
        ConstructionPublishesOnce();
    }

    private static void NamedQueriesPreserveIndependentFacts() {
        var source = Fixture(combinedOwner: false);
        var roots = new[] { new MetadataRecordId(MetadataRecordKind.TypeDefinition, 64) };
        var facts = MetadataFacts.Read(source, new(7), additionalRoots: roots);
        var methodId = new MetadataMethodId(16);
        var method = facts.Method(methodId);
        Check(facts.Name(method.Name.Value).Text.Value == "Generic", "Named method query.");
        Check(facts.GenericArity(methodId).Value == 1, "Generic arity query.");
        Check(facts.Type(new(64)).Methods.Count == 2, "Repeated declarations retained.");
        var declarations = facts.Declarations(roots[0]).Where(d => d.Field == MetadataFieldName.Methods).ToArray();
        Check(declarations.Length == 2 && declarations[0].Ordinal == 0 && declarations[1].Ordinal == 1,
            "Declaration occurrences preserve duplicates and order.");
        Check(declarations[0].Declaration.Value == declarations[1].Declaration.Value, "Shared method identity.");

        source[192] = 255;
        var brokenSignature = MetadataFacts.Read(source, new(7), additionalRoots: roots);
        Check(brokenSignature.Name(brokenSignature.Method(methodId).Name.Value).Text.Value == "Generic",
            "A damaged signature preserves its independent method name.");
        Check(!brokenSignature.GenericArity(methodId).IsAvailable, "Damaged signature arity is unavailable.");
        Check(facts.GenericArity(methodId).Value == 1, "Owned source is unaffected by caller mutation.");

        source = Fixture(combinedOwner: false);
        source[161] = 255;
        var brokenName = MetadataFacts.Read(source, new(7), additionalRoots: roots);
        var nameReference = brokenName.Method(methodId).Name;
        Check(nameReference.IsAvailable, "A malformed name retains its available name identity.");
        var name = brokenName.Name(nameReference.Value);
        Check((brokenName.Field(methodId.Record, MetadataFieldName.Name).Status & MetadataFactStatus.InvalidUtf8) != 0,
            "Raw field inspection retains the target name quality diagnostic.");
        Check(!name.Text.IsAvailable && name.Bytes[0] == 255 && name.Source.Offset == 161,
            "Invalid UTF-8 remains available as original bytes and provenance.");
        Check(brokenName.GenericArity(methodId).Value == 1, "A damaged name preserves valid arity.");
    }

    private static void OwnershipNormalizesAcrossEncodings() {
        foreach (bool combined in new[] { false, true }) {
            foreach (int handleBits in new[] { 7, 8 }) {
                var encoding = new MetadataEncoding(handleBits, CombinedTypeOwnership: combined);
                var source = Fixture(combined, handleBits);
                var id = new MetadataTypeId(64);
                var facts = MetadataFacts.Read(source, encoding, additionalRoots: [id.Record]);
                var owner = facts.Type(id).Owner;
                Check(owner.IsAvailable && owner.Value == new MetadataRecordId(MetadataRecordKind.NamespaceDefinition, 128),
                    "Type ownership is semantic across handle widths and owner encodings.");
            }
        }
    }

    private static void ReferenceOwnershipNormalizesAcrossEncodings() {
        foreach (bool combined in new[] { false, true }) {
            foreach (int handleBits in new[] { 7, 8 }) {
                var source = Fixture(combined, handleBits);
                var encoding = new MetadataEncoding(handleBits, CombinedTypeOwnership: combined);
                int position = 32;
                Write(source, ref position, 128U << handleBits | 48U);
                Write(source, ref position, 160);
                var id = new MetadataRecordId(MetadataRecordKind.TypeReference, 32);
                var construction = new MetadataFacts.Builder(source, encoding, MetadataReadLimits.Default, default);
                construction.AddRoot(id);
                construction.ReadRoots();
                var builtOwner = construction.ReferenceOwner(id);
                var facts = construction.Build();
                var reference = facts.TypeReference(id);
                Check(reference.Owner.IsAvailable && reference.Owner.Value == new MetadataRecordId(MetadataRecordKind.NamespaceReference, 128),
                    "Type-reference ownership is semantic across source field names and handle widths.");
                Check(builtOwner == reference.Owner, "Construction and published ownership agree.");
                Check(facts.Name(reference.Name.Value).Text.Value == "Generic", "Type-reference name is named and available.");
            }
        }
    }

    private static void DamagedEnclosingOwnerPreservesNamespace() {
        var source = Fixture(false);
        var type = new MetadataTypeId(64);
        var facts = MetadataFacts.Read(source, new(7), additionalRoots: [type.Record]);
        var enclosing = facts.Field(type.Record, MetadataFieldName.EnclosingType);
        source[enclosing.Source.Offset] = 255;
        var damaged = MetadataFacts.Read(source, new(7), additionalRoots: [type.Record]);
        Check(!damaged.Type(type).Owner.IsAvailable, "A missing enclosing owner cannot be guessed from its namespace.");
        var physicalNamespace = damaged.Field(type.Record, MetadataFieldName.NamespaceDefinition).Reference;
        Check(physicalNamespace.IsAvailable && physicalNamespace.Value.Offset == 128,
            "A damaged enclosing owner preserves the independently encoded namespace relationship.");
    }

    private static void OldConstantKindsRetainSourceIdentity() {
        (uint SourceKind, MetadataRecordKind Kind)[] legacyKinds = [
            (5, MetadataRecordKind.ConstantEnumValue),
            (6, MetadataRecordKind.ConstantByteArray),
            (7, MetadataRecordKind.ConstantByteValue),
            (8, MetadataRecordKind.ConstantCharArray),
            (9, MetadataRecordKind.ConstantCharValue),
            (10, MetadataRecordKind.ConstantDoubleArray),
            (11, MetadataRecordKind.ConstantDoubleValue),
            (12, MetadataRecordKind.ConstantEnumArray)
        ];
        foreach (var entry in legacyKinds) {
            var encoding = new MetadataEncoding(8, LegacyConstants: true);
            uint raw = 32U << 8 | entry.SourceKind;
            var id = encoding.DecodeHandle(raw);
            Check(id.Kind == entry.Kind && id.Offset == 32 && encoding.EncodeHandle(id) == raw,
                "Legacy constant kind normalization preserves raw handle roundtrip.");
        }

        byte[] source = new byte[224];
        Header(source);
        int position = 32;
        Write(source, ref position, 8);
        for (int i = 0; i < legacyKinds.Length; i++) {
            Write(source, ref position, (uint)(64 + i * 16) << 8 | legacyKinds[i].SourceKind);
        }
        source[96] = 0xA5;
        position = 128;
        Write(source, ref position, 0xD800);
        BinaryPrimitives.WriteUInt64LittleEndian(source.AsSpan(160), 0x8000000000000000UL);
        var arrayId = new MetadataRecordId(MetadataRecordKind.ConstantHandleArray, 32);
        var facts = MetadataFacts.Read(source, new(8, LegacyConstants: true), additionalRoots: [arrayId]);
        var values = facts.Field(arrayId, MetadataFieldName.Value).Items;
        Check(values.Count == legacyKinds.Length, "Every old constant reference is retained.");
        for (int i = 0; i < legacyKinds.Length; i++) {
            var reference = values[i].Reference;
            Check(reference.IsAvailable && reference.Value.Kind == legacyKinds[i].Kind,
                "Legacy source references select the correct canonical record decoder.");
        }
        var byteId = new MetadataRecordId(MetadataRecordKind.ConstantByteValue, 96);
        Check(facts.Field(byteId, MetadataFieldName.Value).UInt32.Value == 0xA5, "Legacy byte record consumed.");
        Check(facts.RawHandle(byteId) == (96U << 8 | 7), "Legacy byte raw kind retained.");
        Check(facts.Field(values[4].Reference.Value, MetadataFieldName.Value).Character.Value == '\uD800',
            "Legacy character constants preserve lone UTF-16 code units.");
        Check(facts.Field(values[6].Reference.Value, MetadataFieldName.Value).Bits == 0x8000000000000000UL,
            "Legacy floating constants preserve negative-zero bits.");
    }

    private static void InvalidHandleEncodingIsExternalData() {
        foreach (uint raw in new uint[] { 32U << 8 | 200U, 32U << 8 }) {
            bool rejected = false;
            try {
                new MetadataEncoding(8).DecodeHandle(raw);
            } catch (InvalidDataException) {
                rejected = true;
            }
            Check(rejected, "Malformed external handle reports a data error.");
        }
    }

    private static void CollectionPrefixSurvivesDamage() {
        byte[] source = new byte[35];
        Header(source);
        // Int32 collection: declared count 3, first two values 1 and -1,
        // followed by EOF. The missing third item retains its fault location.
        source[32] = 6;
        source[33] = 2;
        source[34] = 254;
        var id = new MetadataRecordId(MetadataRecordKind.ConstantInt32Array, 32);
        var facts = MetadataFacts.Read(source, new(7), additionalRoots: [id]);
        var values = facts.Field(id, MetadataFieldName.Value).Items;
        Check(values.DeclaredCount == 3 && values.Count == 3, "Decoded items and failed occurrence retained.");
        Check(values[0].Int32.Value == 1 && values[1].Int32.Value == -1, "Signed prefix values retained.");
        Check((values[2].Status & MetadataFactStatus.Truncated) != 0, "Missing item explicitly truncated.");
        Check(values[2].Source.Offset == source.Length && values[2].Source.Length == 0, "Missing item location retained.");
    }

    private static void ResourceLimitsRemainQueryable() {
        var id = new MetadataTypeId(64);
        var facts = MetadataFacts.Read(Fixture(false), new(7), new(4, 1, 0), additionalRoots: [id.Record]);
        var owner = facts.Type(id).Owner;
        Check(!owner.IsAvailable && (owner.Status & MetadataFactStatus.LimitExceeded) != 0,
            "An exhausted type still returns explicit unavailable owner facts.");
        Check((facts.Status & MetadataFactStatus.LimitExceeded) != 0, "Resource exhaustion remains visible.");
    }

    private static void CancellationStopsConstruction() {
        using var cancellation = new CancellationTokenSource();
        cancellation.Cancel();
        bool cancelled = false;
        try {
            MetadataFacts.Read(Fixture(false), new(7), cancellationToken: cancellation.Token);
        } catch (OperationCanceledException) {
            cancelled = true;
        }
        Check(cancelled, "Construction observes cancellation before publishing.");
    }

    private static void NegativeArityRetainsRawBits() {
        var source = Fixture(false);
        source[193] = 254;
        var method = new MetadataMethodId(16);
        var facts = MetadataFacts.Read(source, new(7), additionalRoots: [method.Record]);
        var arity = facts.GenericArity(method);
        Check(arity.Value == -1 && !arity.IsAvailable && (arity.Status & MetadataFactStatus.InvalidNumeric) != 0,
            "Negative arity is invalid without discarding its encoded signed value.");
    }

    private static void DamagedStringPrefixHasNoInventedPayload() {
        var source = Fixture(false);
        source[160] = 255;
        var methodId = new MetadataMethodId(16);
        var facts = MetadataFacts.Read(source, new(7), additionalRoots: [methodId.Record]);
        var nameReference = facts.Method(methodId).Name;
        var name = facts.Name(nameReference.Value);
        Check(nameReference.IsAvailable && !name.Text.IsAvailable, "A malformed string prefix preserves its known record identity.");
        Check(name.Bytes.IsEmpty && !name.Source.IsAvailable, "An undecoded string length cannot invent a payload boundary.");
        var encoded = facts.Field(nameReference.Value.Record, MetadataFieldName.Value);
        Check(encoded.Source.Offset == 160 && encoded.EncodedBytes.SequenceEqual(new byte[] { 255 }),
            "The malformed prefix retains its original encoded byte and source range.");
    }

    private static void InvalidRootHasNoSourceRange() {
        var id = new MetadataRecordId(MetadataRecordKind.Method, 4096);
        var facts = MetadataFacts.Read(Fixture(false), new(7), additionalRoots: [id]);
        var record = facts.Record(id);
        Check(!record.Source.IsAvailable && (record.Status & MetadataFactStatus.InvalidHandle) != 0,
            "Out-of-bounds roots have no invented source provenance.");
    }

    private static void ConstructionPublishesOnce() {
        var method = new MetadataMethodId(16);
        var construction = new MetadataFacts.Builder(Fixture(false), new(7), MetadataReadLimits.Default, default);
        construction.AddRoot(method.Record);
        construction.ReadRoots();
        var name = construction.Field(method.Record, MetadataFieldName.Name).Reference;
        var type = new MetadataTypeId(64);
        construction.AddRoot(type.Record);
        construction.ReadRoots();
        var published = construction.Build();
        Check(published.Contains(type.Record) && published.Method(method).Name.Value.Offset == name.Value.Offset,
            "Later roots preserve previously accepted identities and provenance.");
        Check(published.Name(published.Method(method).Name.Value).Text.Value == "Generic",
            "Publication retains independently usable names.");

        bool rejected = false;
        try {
            construction.AddRoot(new(MetadataRecordKind.Method, 20));
        } catch (InvalidOperationException) {
            rejected = true;
        }
        Check(rejected, "Published construction cannot mutate the snapshot's handle index.");
        rejected = false;
        try {
            construction.Build();
        } catch (InvalidOperationException) {
            rejected = true;
        }
        Check(rejected, "Construction publishes exactly once.");
    }

    private static byte[] Fixture(bool combinedOwner, int handleBits = 7) {
        byte[] source = new byte[224];
        Header(source);
        int position = 16;
        Write(source, ref position, 0); // method flags
        Write(source, ref position, 0); // implementation flags
        Write(source, ref position, 160); // name
        Write(source, ref position, 192); // signature
        Write(source, ref position, 0); // parameters
        Write(source, ref position, 0); // generic parameters
        Write(source, ref position, 0); // custom attributes

        position = 64;
        Write(source, ref position, 0); // type flags
        Write(source, ref position, 0); // base type
        Write(source, ref position, combinedOwner ? 128U << handleBits | 47U : 128U);
        Write(source, ref position, 160); // name
        Write(source, ref position, 0); // size
        Write(source, ref position, 0); // packing
        if (!combinedOwner) {
            Write(source, ref position, 0); // enclosing type
        }
        Write(source, ref position, 0); // nested types
        Write(source, ref position, 2); // methods
        Write(source, ref position, 16);
        Write(source, ref position, 16);
        for (int i = 0; i < 6; i++) {
            Write(source, ref position, 0); // fields, properties, events, generics, interfaces, attributes
        }

        position = 128;
        for (int i = 0; i < 5; i++) {
            Write(source, ref position, 0); // namespace parent, name and collections
        }
        position = 160;
        Write(source, ref position, 7);
        Encoding.UTF8.GetBytes("Generic", source.AsSpan(position));
        position = 192;
        Write(source, ref position, 0); // calling convention
        Write(source, ref position, 1); // generic parameter count
        Write(source, ref position, 0); // return type
        Write(source, ref position, 0); // parameters
        Write(source, ref position, 0); // vararg parameters
        return source;
    }

    private static void Header(byte[] source) {
        BinaryPrimitives.WriteUInt32LittleEndian(source, 0xDEADDFFD);
        source[4] = 0;
    }

    private static void Write(byte[] source, ref int position, uint value) {
        if (value < 128) {
            source[position++] = (byte)(value << 1);
        } else if (value < 16384) {
            source[position++] = (byte)(value << 2 | 1);
            source[position++] = (byte)(value >> 6);
        } else if (value < 2097152) {
            source[position++] = (byte)(value << 3 | 3);
            source[position++] = (byte)(value >> 5);
            source[position++] = (byte)(value >> 13);
        } else {
            source[position++] = 15;
            BinaryPrimitives.WriteUInt32LittleEndian(source.AsSpan(position), value);
            position += 4;
        }
    }

    private static void Check(bool condition, string message) {
        if (!condition) {
            throw new InvalidOperationException(message);
        }
    }
}
