using System.Runtime.InteropServices;
using System.Buffers.Binary;
using System.Text;

namespace Atlas.Binja;

internal sealed unsafe class AnnotationReconciliation : IDisposable {
    internal readonly record struct OwnedCounts(uint Symbols, uint Variables, uint References);

    private enum SnapshotTypeKind : byte {
        Structure = 4,
        Pointer = 6,
        Array = 7,
        Function = 8,
        NamedReference = 11,
        Fragment = 13
    }

    private enum Kind : byte {
        Type,
        Symbol,
        Variable,
        Reference,
        Function,
        Abi,
        Tag,
        Metadata,
        Field
    }

    private readonly record struct Key(Kind Kind, ulong Address = 0, ulong Target = 0, string Id = "");
    private readonly record struct TagSite(ulong Address, ulong Kind, string Category, string Slot);
    private readonly record struct TagTypeIdentity(string Category, string NativeId);

    private sealed class SymbolSnapshot {
        internal byte Kind;
        internal required string ShortName;
        internal required string FullName;
        internal required string RawName;
        internal byte Binding;
        internal ulong Ordinal;
        internal required string Join;
        internal string[] Namespace = [];
    }

    private sealed class Fact {
        internal required Key Key;
        internal string[] Text = [];
        // Signed enum types retain a marker independently of native snapshots,
        // which may lose the same signedness bit as BNDB reload.
        internal byte[] Bytes = [];
        internal nint Type;
        internal nint PriorType;
        internal bool Excluded;
        internal bool Seen;
        internal bool Automatic;
        internal ulong Size;
        internal byte Confidence;
        internal SymbolSnapshot? Symbol;
    }

    [ThreadStatic]
    internal static AnnotationReconciliation? Current;

    internal nint View { get; }
    internal bool LegacyOwnershipMissing { get; private set; }
    internal bool LegacyTagIdentityMissing { get; private set; }
    private readonly ulong imageBase;
    private readonly nint platform;
    private readonly Dictionary<Key, Fact> facts = [];
    private readonly Dictionary<string, Key> tagKeys = [];
    private readonly Dictionary<TagSite, Fact> tagSites = [];
    private readonly Dictionary<nint, TagTypeIdentity> tagTypes = [];
    private readonly List<(Fact? Before, Fact After)> changes = [];
    private readonly List<nint> types = [];
    private readonly HashSet<string> retiredTags = [];
    private readonly List<nint> registeredTags = [];
    private readonly string temporary;
    private readonly bool fieldsOnly;
    private readonly CancellationToken cancellationToken;
    private bool complete;
    private bool disposed;
    private bool nativeIdentityRecovered;
    private byte[]? generation;

    internal AnnotationReconciliation(nint view, bool fieldsOnly = false, CancellationToken cancellationToken = default) {
        cancellationToken.ThrowIfCancellationRequested();

        if (Current != null)
            throw new InvalidOperationException("An Atlas annotation operation is already active on this thread.");

        View = view;
        this.fieldsOnly = fieldsOnly;
        this.cancellationToken = cancellationToken;
        imageBase = Core.BNGetImageBase(view);
        platform = Core.BNGetDefaultPlatform(view);
        if (platform == 0)
            throw new NotSupportedException("The Binary Ninja view has no default platform.");

        temporary = Path.Combine(Path.GetTempPath(), "aot-atlas-types-" + Guid.NewGuid().ToString("N"));

        try {
            Read();
            Current = this;
        } finally {
            if (Current != this) {
                foreach (nint type in types)
                    Core.BNFreeType(type);
                Core.BNFreePlatform(platform);
                File.Delete(temporary);
            }
        }
    }

    private static string Text(byte* value) => Marshal.PtrToStringUTF8((nint)value) ?? "";

    private static string TakeText(byte* value) {
        if (value == null)
            throw new IOException("Binary Ninja did not return annotation text.");
        string text = Text(value);
        Core.BNFreeString(value);
        return text;
    }

    private static string[] Name(QualifiedName name) {
        string[] text = new string[checked((int)name.Count)];
        for (int i = 0; i < text.Length; ++i)
            text[i] = Text(name.Names[i]);
        return text;
    }

    private static QualifiedName NativeName(string[] text, out byte[] buffer, string join = "::") {
        int length = Encoding.UTF8.GetByteCount(join) + 1;
        foreach (string part in text)
            length = checked(length + Encoding.UTF8.GetByteCount(part) + 1);
        buffer = new byte[length];
        Encoding.UTF8.GetBytes(join, buffer);
        return new QualifiedName { Count = (nuint)text.Length };
    }

    private static void FillName(QualifiedName* name, byte* bytes, byte** parts, string[] text) {
        name->Names = parts;
        name->Join = bytes;
        int position = MemoryMarshal.CreateReadOnlySpanFromNullTerminated(bytes).Length + 1;
        for (int i = 0; i < text.Length; ++i) {
            parts[i] = bytes + position;
            position += Encoding.UTF8.GetBytes(text[i], new Span<byte>(bytes + position, Encoding.UTF8.GetByteCount(text[i])));
            bytes[position++] = 0;
        }
    }

    private nint Retain(nint type) {
        if (type == 0)
            return 0;
        nint retained = Core.BNNewTypeReference(type);
        types.Add(retained);
        return retained;
    }

    private static byte[] Raw(nint metadata) {
        if (Core.BNMetadataIsRaw(metadata) == 0)
            throw new InvalidDataException("An Atlas annotation record is not raw metadata.");
        nuint length = 0;
        byte* bytes = Core.BNMetadataGetRaw(metadata, &length);
        try {
            return new ReadOnlySpan<byte>(bytes, checked((int)length)).ToArray();
        } finally {
            Core.BNFreeMetadataRaw(bytes);
        }
    }

    private void Read() {
        nint metadata;
        fixed (byte* key = "aot-atlas:owned-annotations\0"u8)
            metadata = Core.BNBinaryViewQueryMetadata(View, key);

        if (metadata == 0) {
            // Native automatic type IDs prove their producer. Legacy user symbols,
            // variables and references have no recoverable ownership evidence.
            nuint count = 0;
            var entries = Core.BNGetAnalysisTypeList(View, &count);
            try {
                for (nuint i = 0; i < count; ++i) {
                    cancellationToken.ThrowIfCancellationRequested();

                    string id = TakeText(Core.BNGetAnalysisTypeId(View, &entries[i].Name));
                    if (!id.StartsWith("aot-atlas:", StringComparison.Ordinal)
                        || Core.BNIsAnalysisTypeAutoDefined(View, &entries[i].Name) == 0)
                        continue;
                    var key = new Key(Kind.Type, Id: id);
                    facts.Add(key, new Fact {
                        Key = key,
                        Text = Name(entries[i].Name),
                        Type = Retain(entries[i].Type),
                        Bytes = Core.BNGetTypeClass(entries[i].Type) == 5 && Core.BNIsTypeSigned(entries[i].Type).Value != 0 ? [1] : [],
                        Automatic = true
                    });
                }
            } finally {
                Core.BNFreeTypeAndNameList(entries, count);
            }
            LegacyOwnershipMissing = facts.Count != 0;
            return;
        }

        byte[] bytes;
        try {
            bytes = Raw(metadata);
            generation = bytes;
        } finally {
            Core.BNFreeMetadata(metadata);
        }

        using var input = new MemoryStream(bytes, writable: false);
        using var reader = new BinaryReader(input, Encoding.UTF8);
        if (!reader.ReadBytes(8).AsSpan().SequenceEqual("ATOWN001"u8))
            throw new InvalidDataException("The Atlas annotation ownership header is invalid.");

        int libraryLength = reader.ReadInt32();
        if (libraryLength <= 0 || libraryLength > input.Length - input.Position - 4)
            throw new InvalidDataException("The Atlas annotation type snapshot is truncated.");
        File.WriteAllBytes(temporary, reader.ReadBytes(libraryLength));

        nint library;
        byte[] path = Encoding.UTF8.GetBytes(temporary + '\0');
        fixed (byte* value = path)
            library = Core.BNLoadTypeLibraryFromFile(value);
        if (library == 0)
            throw new InvalidDataException("Binary Ninja could not load the Atlas annotation type snapshot.");

        try {
            int count = reader.ReadInt32();
            if (count < 0 || count > (input.Length - input.Position) / 29)
                throw new InvalidDataException("The Atlas annotation count exceeds its record.");
            facts.EnsureCapacity(count);
            for (int i = 0; i < count; ++i) {
                cancellationToken.ThrowIfCancellationRequested();

                var key = new Key((Kind)reader.ReadByte(), reader.ReadUInt64(), reader.ReadUInt64(), reader.ReadString());
                if (key.Kind > Kind.Field || key.Id.Contains('\0'))
                    throw new InvalidDataException("An Atlas annotation identity is invalid.");
                var fact = new Fact { Key = key, Excluded = reader.ReadBoolean(), Automatic = reader.ReadBoolean() };
                int textCount = reader.ReadInt32();
                if (textCount < 0 || textCount > (input.Length - input.Position) / 1)
                    throw new InvalidDataException("An Atlas annotation name is truncated.");
                fact.Text = new string[textCount];
                for (int j = 0; j < textCount; ++j) {
                    fact.Text[j] = reader.ReadString();
                    if (fact.Text[j].Contains('\0'))
                        throw new InvalidDataException("An Atlas annotation name contains a NUL.");
                }
                fact.Type = SnapshotType(library, reader.ReadInt32());
                fact.PriorType = SnapshotType(library, reader.ReadInt32());
                fact.Size = reader.ReadUInt64();
                fact.Confidence = reader.ReadByte();
                if (reader.ReadBoolean()) {
                    fact.Symbol = new SymbolSnapshot {
                        Kind = reader.ReadByte(),
                        ShortName = reader.ReadString(),
                        FullName = reader.ReadString(),
                        RawName = reader.ReadString(),
                        Binding = reader.ReadByte(),
                        Ordinal = reader.ReadUInt64(),
                        Join = reader.ReadString()
                    };
                    int namespaceCount = reader.ReadInt32();
                    if (namespaceCount < 0 || namespaceCount > input.Length - input.Position)
                        throw new InvalidDataException("An Atlas symbol namespace is truncated.");

                    fact.Symbol.Namespace = new string[namespaceCount];
                    for (int j = 0; j < namespaceCount; ++j)
                        fact.Symbol.Namespace[j] = reader.ReadString();
                }

                int length = reader.ReadInt32();
                if (length < 0 || length > input.Length - input.Position)
                    throw new InvalidDataException("An Atlas annotation value is truncated.");
                fact.Bytes = reader.ReadBytes(length);
                Validate(fact);
                if (key.Kind == Kind.Type && !fact.Excluded && fact.Bytes.Length == 0
                    && Core.BNGetTypeClass(fact.Type) == 5 && Core.BNIsTypeSigned(fact.Type).Value != 0)
                    fact.Bytes = [1];
                if (key.Kind == Kind.Tag && !fact.Excluded && fact.Text.Length == 1) {
                    nativeIdentityRecovered = true;
                    UpgradeTagIdentity(fact);
                }
                if (key.Kind == Kind.Tag && fact.Excluded && fact.Text.Length == 0)
                    LegacyTagIdentityMissing = true;
                if (!facts.TryAdd(key, fact))
                    throw new InvalidDataException("An Atlas annotation identity is repeated.");
                if (key.Kind == Kind.Tag)
                    tagKeys.Add(key.Id, key);
                IndexTag(fact);
            }
            if (input.Position != input.Length)
                throw new InvalidDataException("The Atlas annotation record has trailing bytes.");
            RecoverEnumSignedness();
        } finally {
            Core.BNFreeTypeLibrary(library);
            File.Delete(temporary);
        }
    }

    private static void Validate(Fact fact) {
        if (fact.Excluded) {
            bool tagIdentity = fact.Key.Kind == Kind.Tag && fact.Text.Length == 3 && fact.Text[0].Length != 0
                && fact.Text[2] is "deleted" or "edited";
            bool inputFormat = fact.Key.Kind == Kind.Metadata && fact.Key.Id == "aot-atlas:apply-input"
                && fact.Text.Length == 1 && byte.TryParse(fact.Text[0], out byte format) && format <= (byte)MapFormat.Metadata;
            if (fact.Type != 0 || fact.PriorType != 0 || (fact.Text.Length != 0 && !tagIdentity && !inputFormat)
                || fact.Symbol != null || fact.Bytes.Length != 0 || fact.Size != 0 || fact.Confidence != 0)
                throw new InvalidDataException("An Atlas ownership exclusion contains annotation state.");

            return;
        }

        bool valid = fact.Key.Kind switch {
            Kind.Type => fact.Type != 0 && fact.PriorType == 0 && fact.Text.Length != 0
                && fact.Symbol == null && (fact.Bytes.Length == 0 || (fact.Bytes.Length == 1 && fact.Bytes[0] == 1)) && fact.Automatic
                && fact.Key.Id.StartsWith("aot-atlas:", StringComparison.Ordinal)
                && fact.Key.Address == 0 && fact.Key.Target == 0,
            Kind.Symbol => fact.Type == 0 && fact.PriorType == 0 && fact.Text.Length == 0
                && fact.Symbol != null && fact.Bytes.Length == 0 && !fact.Automatic
                && fact.Key.Id.Length == 0 && fact.Key.Target == 0,
            Kind.Variable => fact.Type != 0 && fact.PriorType == 0 && fact.Text.Length == 0
                && fact.Symbol == null && fact.Bytes.Length == 0 && !fact.Automatic
                && fact.Key.Id.Length == 0 && fact.Key.Target == 0,
            Kind.Reference => fact.Type == 0 && fact.PriorType == 0 && fact.Text.Length == 0
                && fact.Symbol == null && fact.Bytes.Length == 0 && !fact.Automatic
                && fact.Key.Id.Length == 0,
            Kind.Function => fact.Type == 0 && fact.PriorType == 0 && fact.Text.Length == 0
                && fact.Symbol == null && fact.Bytes.Length == 0 && fact.Automatic
                && fact.Key.Id.Length == 0 && fact.Key.Target == 0,
            Kind.Abi => fact.Type != 0 && fact.PriorType != 0 && fact.Text.Length == 0
                && fact.Symbol == null && fact.Bytes.Length != 0 && fact.Automatic
                && fact.Key.Id.Length == 0 && fact.Key.Target == 0,
            Kind.Tag => fact.Type == 0 && fact.PriorType == 0 && fact.Text.Length is 1 or 4
                && (fact.Text.Length == 1 || (fact.Text[1].Length != 0 && fact.Text[3].Length != 0))
                && fact.Symbol == null && fact.Bytes.Length == 0 && !fact.Automatic
                && fact.Key.Id.Length != 0 && fact.Key.Target <= 1,
            Kind.Metadata => fact.Type == 0 && fact.PriorType == 0 && fact.Text.Length == 0
                && fact.Symbol == null && !fact.Automatic
                && fact.Key.Id.StartsWith("aot-atlas:", StringComparison.Ordinal)
                && fact.Key.Address == 0 && fact.Key.Target == 0,
            Kind.Field => fact.Type == 0 && fact.PriorType == 0 && fact.Text.Length != 0
                && fact.Symbol == null && fact.Bytes.Length == 0 && !fact.Automatic,
            _ => false
        };

        if (fact.Key.Kind != Kind.Variable && fact.Confidence != 0)
            valid = false;
        if (fact.Key.Kind != Kind.Field && fact.Size != 0)
            valid = false;
        if (fact.Key.Kind == Kind.Type && fact.Bytes.Length == 1 && Core.BNGetTypeClass(fact.Type) != 5)
            valid = false;

        if (fact.Symbol is { } symbol) {
            valid &= symbol.Kind <= 8 && symbol.Binding <= 3
                && !symbol.ShortName.Contains('\0') && !symbol.FullName.Contains('\0')
                && !symbol.RawName.Contains('\0') && !symbol.Join.Contains('\0');
            foreach (string part in symbol.Namespace)
                valid &= !part.Contains('\0');
        }

        if (fact.Key.Kind == Kind.Field) {
            int first = fact.Key.Id.IndexOf(':');
            int second = first < 0 ? -1 : fact.Key.Id.IndexOf(':', first + 1);
            valid &= first > 0 && second > first + 1;
            if (valid) {
                valid = ulong.TryParse(fact.Key.Id.AsSpan(0, first), System.Globalization.NumberStyles.HexNumber,
                        System.Globalization.CultureInfo.InvariantCulture, out _)
                    && ulong.TryParse(fact.Key.Id.AsSpan(first + 1, second - first - 1), System.Globalization.NumberStyles.HexNumber,
                        System.Globalization.CultureInfo.InvariantCulture, out ulong size)
                    && size == fact.Size
                    && fact.Key.Id[(second + 1)..] == NameKey(fact.Text);
            }
        }

        if (!valid)
            throw new InvalidDataException($"The stored Atlas {fact.Key.Kind} annotation record has an invalid shape.");
    }

    private nint SnapshotType(nint library, int index) {
        if (index == -1)
            return 0;
        if (index < 0)
            throw new InvalidDataException("An Atlas annotation type index is invalid.");
        byte[] text = Encoding.UTF8.GetBytes(index.ToString("X8") + '\0');
        fixed (byte* value = text)
        fixed (byte* join = "::\0"u8) {
            byte** parts = stackalloc byte*[1] { value };
            var name = new QualifiedName { Names = parts, Join = join, Count = 1 };
            nint type = Core.BNGetTypeLibraryNamedType(library, &name);
            if (type == 0)
                throw new InvalidDataException("An Atlas annotation type snapshot is missing.");
            types.Add(type);
            return type;
        }
    }

    private int StoreType(nint library, nint type, Dictionary<nint, int> indexes) {
        if (type == 0)
            return -1;
        if (indexes.TryGetValue(type, out int index))
            return index;
        index = indexes.Count;
        byte[] text = Encoding.UTF8.GetBytes(index.ToString("X8") + '\0');
        fixed (byte* value = text)
        fixed (byte* join = "::\0"u8) {
            byte** parts = stackalloc byte*[1] { value };
            var name = new QualifiedName { Names = parts, Join = join, Count = 1 };
            Core.BNBinaryViewExportTypeToTypeLibrary(View, library, &name, type);
        }
        indexes.Add(type, index);
        return index;
    }

    private OwnedCounts Save() {
        nint library;
        fixed (byte* name = "Atlas annotation provenance\0"u8)
            library = Core.BNNewTypeLibrary(Core.BNGetPlatformArchitecture(platform), name);
        if (library == 0)
            throw new IOException("Binary Ninja could not create the Atlas annotation type snapshot.");

        using var records = new MemoryStream();
        using var writer = new BinaryWriter(records, Encoding.UTF8, leaveOpen: true);
        uint symbols = 0;
        uint variables = 0;
        uint references = 0;
        try {
            var typeIndexes = new Dictionary<nint, int>();
            writer.Write(facts.Count);
            foreach (var fact in facts.Values) {
                cancellationToken.ThrowIfCancellationRequested();

                if (!fact.Excluded) {
                    switch (fact.Key.Kind) {
                        case Kind.Symbol:
                            ++symbols;
                            break;
                        case Kind.Variable:
                            ++variables;
                            break;
                        case Kind.Reference:
                            ++references;
                            break;
                    }
                }

                writer.Write((byte)fact.Key.Kind);
                writer.Write(fact.Key.Address);
                writer.Write(fact.Key.Target);
                writer.Write(fact.Key.Id);
                writer.Write(fact.Excluded);
                writer.Write(fact.Automatic);
                writer.Write(fact.Text.Length);
                foreach (string text in fact.Text)
                    writer.Write(text);
                writer.Write(StoreType(library, fact.Type, typeIndexes));
                writer.Write(StoreType(library, fact.PriorType, typeIndexes));
                writer.Write(fact.Size);
                writer.Write(fact.Confidence);
                writer.Write(fact.Symbol != null);
                if (fact.Symbol is { } symbol) {
                    writer.Write(symbol.Kind);
                    writer.Write(symbol.ShortName);
                    writer.Write(symbol.FullName);
                    writer.Write(symbol.RawName);
                    writer.Write(symbol.Binding);
                    writer.Write(symbol.Ordinal);
                    writer.Write(symbol.Join);
                    writer.Write(symbol.Namespace.Length);
                    foreach (string part in symbol.Namespace)
                        writer.Write(part);
                }

                writer.Write(fact.Bytes.Length);
                writer.Write(fact.Bytes);
            }
            cancellationToken.ThrowIfCancellationRequested();

            PreserveForwardDeclarations(library);
            byte[] path = Encoding.UTF8.GetBytes(temporary + '\0');
            fixed (byte* value = path) {
                if (Core.BNFinalizeTypeLibrary(library) == 0 || Core.BNWriteTypeLibraryToFile(library, value) == 0)
                    throw new IOException("Binary Ninja could not save the Atlas annotation type snapshot.");
            }
            int recordLength = checked((int)records.Length);
            byte[] bytes;
            int snapshotLength;
            using (var snapshot = File.OpenRead(temporary)) {
                snapshotLength = checked((int)snapshot.Length);
                bytes = new byte[checked(12 + snapshotLength + recordLength)];
                "ATOWN001"u8.CopyTo(bytes);
                BinaryPrimitives.WriteInt32LittleEndian(bytes.AsSpan(8), snapshotLength);
                snapshot.ReadExactly(bytes.AsSpan(12, snapshotLength));
            }
            records.Position = 0;
            records.ReadExactly(bytes.AsSpan(12 + snapshotLength, recordLength));
            cancellationToken.ThrowIfCancellationRequested();

            var keyValue = new Key(Kind.Metadata, Id: "aot-atlas:owned-annotations");
            Fact? before = Capture(keyValue);
            // Publication can succeed even when the acknowledgement is lost.
            // Journal the receipt before writing so rollback checks the published value.
            changes.Add((before, new Fact { Key = keyValue, Bytes = bytes }));
            fixed (byte* key = "aot-atlas:owned-annotations\0"u8)
            fixed (byte* value = bytes) {
                nint metadata = Core.BNCreateMetadataRawData(value, (nuint)bytes.Length);
                if (metadata == 0)
                    throw new IOException("Binary Ninja could not create the Atlas annotation ownership record.");
                try {
                    Core.StoreMetadataRaw(View, key, metadata, 3);
                    nint stored = Core.BNBinaryViewQueryMetadata(View, key);
                    if (stored == 0)
                        throw new IOException("Binary Ninja did not acknowledge the Atlas annotation ownership record.");
                    try {
                        if (!Raw(stored).AsSpan().SequenceEqual(bytes))
                            throw new IOException("Binary Ninja did not retain the Atlas annotation ownership record.");
                    } finally {
                        Core.BNFreeMetadata(stored);
                    }
                } finally {
                    Core.BNFreeMetadata(metadata);
                }
            }
        } finally {
            Core.BNFreeTypeLibrary(library);
            File.Delete(temporary);
        }
        return new OwnedCounts(symbols, variables, references);
    }

    private void PreserveForwardDeclarations(nint library) {
        var visited = new HashSet<nint>();
        var pending = new List<nint>();

        void Add(nint type) {
            if (type != 0 && visited.Add(type))
                pending.Add(Core.BNNewTypeReference(type));
        }

        try {
            nuint count = 0;
            var entries = Core.BNGetTypeLibraryNamedTypes(library, &count);
            try {
                for (nuint i = 0; i < count; ++i)
                    Add(entries[i].Type);
            } finally {
                Core.BNFreeTypeAndNameList(entries, count);
            }

            for (int cursor = 0; cursor < pending.Count; ++cursor) {
                cancellationToken.ThrowIfCancellationRequested();
                nint type = pending[cursor];
                switch ((SnapshotTypeKind)Core.BNGetTypeClass(type)) {
                    case SnapshotTypeKind.Structure: {
                        nint structure = Core.BNGetTypeStructure(type);
                        try {
                            var members = Core.BNGetStructureMembers(structure, &count);
                            try {
                                for (nuint i = 0; i < count; ++i)
                                    Add(members[i].Type);
                            } finally {
                                Core.BNFreeStructureMemberList(members, count);
                            }
                            var bases = Core.BNGetBaseStructuresForStructure(structure, &count);
                            try {
                                BoolConfidence qualifier = default;
                                for (nuint i = 0; i < count; ++i) {
                                    nint reference = Core.BNCreateNamedTypeReference(bases[i].Type,
                                        (nuint)bases[i].Width, 1, &qualifier, &qualifier);
                                    try {
                                        Add(reference);
                                    } finally {
                                        Core.BNFreeType(reference);
                                    }
                                }
                            } finally {
                                Core.BNFreeBaseStructureList(bases, count);
                            }
                        } finally {
                            Core.BNFreeStructure(structure);
                        }
                        break;
                    }
                    case SnapshotTypeKind.Pointer:
                    case SnapshotTypeKind.Array:
                    case SnapshotTypeKind.Fragment: {
                        var child = Core.BNGetChildType(type);
                        try {
                            Add(child.Type);
                        } finally {
                            if (child.Type != 0)
                                Core.BNFreeType(child.Type);
                        }
                        break;
                    }
                    case SnapshotTypeKind.Function: {
                        ReturnValue result = Core.BNGetTypeReturnValue(type);
                        try {
                            Add(result.Type);
                        } finally {
                            Core.BNFreeType(result.Type);
                            Core.BNFreeValueLocation(&result.Location);
                        }
                        var parameters = Core.BNGetTypeParameters(type, &count);
                        try {
                            for (nuint i = 0; i < count; ++i)
                                Add(parameters[i].Type);
                        } finally {
                            Core.BNFreeTypeParameterList(parameters, count);
                        }
                        break;
                    }
                    case SnapshotTypeKind.NamedReference: {
                        nint reference = Core.BNGetTypeNamedTypeReference(type);
                        try {
                            var name = Core.BNGetTypeReferenceName(reference);
                            try {
                                nint existing = Core.BNGetTypeLibraryNamedType(library, &name);
                                if (existing == 0) {
                                    // A self-named reference persists an incomplete declaration
                                    // without assigning it a layout or defining it in the view.
                                    Core.BNAddTypeLibraryNamedType(library, &name, type);
                                } else {
                                    Core.BNFreeType(existing);
                                }
                            } finally {
                                Core.BNFreeQualifiedName(&name);
                            }
                        } finally {
                            Core.BNFreeNamedTypeReference(reference);
                        }
                        break;
                    }
                }
            }
        } finally {
            foreach (nint type in pending)
                Core.BNFreeType(type);
        }
    }

    private Fact? Capture(Key key) {
        var fact = new Fact { Key = key };
        ulong address = imageBase + key.Address;
        byte[] identifier = Encoding.UTF8.GetBytes(key.Id + '\0');
        fixed (byte* id = identifier) {
            switch (key.Kind) {
                case Kind.Type: {
                    nint type = Core.BNGetAnalysisTypeById(View, id);
                    if (type == 0)
                        return null;
                    var name = Core.BNGetAnalysisTypeNameById(View, id);
                    try {
                        fact.Type = Retain(type);
                        fact.Text = Name(name);
                        fact.Automatic = Core.BNIsAnalysisTypeAutoDefined(View, &name) != 0;
                        fact.Bytes = Core.BNGetTypeClass(type) == 5 && Core.BNIsTypeSigned(type).Value != 0 ? [1] : [];
                    } finally {
                        Core.BNFreeQualifiedName(&name);
                        Core.BNFreeType(type);
                    }
                    break;
                }
                case Kind.Symbol: {
                    nint symbol = Core.BNGetSymbolByAddress(View, address, 0);
                    if (symbol == 0)
                        return null;
                    try {
                        fact.Symbol = SymbolState(symbol);
                        fact.Automatic = Core.BNIsSymbolAutoDefined(symbol) != 0;
                    } finally {
                        Core.BNFreeSymbol(symbol);
                    }
                    break;
                }
                case Kind.Variable: {
                    DataVariable variable = default;
                    if (Core.BNGetDataVariableAtAddress(View, address, &variable) == 0)
                        return null;
                    try {
                        fact.Type = Retain(variable.Type);
                        fact.Automatic = variable.AutoDiscovered != 0;
                        fact.Confidence = variable.Confidence;
                    } finally {
                        Core.BNFreeDataVariable(&variable);
                    }
                    break;
                }
                case Kind.Reference: {
                    nuint count = 0;
                    ulong* references = Core.BNGetDataReferencesFrom(View, address, &count);
                    try {
                        if (!new ReadOnlySpan<ulong>(references, checked((int)count)).Contains(imageBase + key.Target))
                            return null;
                    } finally {
                        Core.BNFreeDataReferences(references);
                    }
                    break;
                }
                case Kind.Function:
                case Kind.Abi: {
                    nint function = Core.GetFunction(View, platform, address);
                    if (function == 0)
                        return null;
                    try {
                        fact.Automatic = key.Kind == Kind.Abi
                            ? Core.BNFunctionHasUserType(function) == 0
                            : Core.BNFunctionHasUserAnnotations(function) == 0;
                        if (key.Kind == Kind.Abi) {
                            nint type = Core.BNGetFunctionType(function);
                            fact.Type = Retain(type);
                            fact.Bytes = AbiMetadata(type);
                            Core.BNFreeType(type);
                        }
                    } finally {
                        Core.BNFreeFunction(function);
                    }
                    break;
                }
                case Kind.Tag: {
                    nint tag = Core.BNGetTag(View, id);
                    if (tag == 0)
                        return null;
                    try {
                        nint tagType = Core.BNTagGetType(tag);
                        nint function = key.Target == 1 ? 0 : Core.GetFunction(View, platform, address);
                        nuint count = 0;
                        nint* tags = key.Target == 1
                            ? Core.BNGetUserDataTagsOfType(View, address, tagType, &count)
                            : function == 0 ? null : Core.BNGetUserFunctionTagsOfType(function, tagType, &count);
                        bool found;
                        try {
                            found = new ReadOnlySpan<nint>(tags, checked((int)count)).Contains(tag);
                        } finally {
                            Core.BNFreeTagList(tags, count);
                            Core.BNFreeTagType(tagType);
                            if (function != 0)
                                Core.BNFreeFunction(function);
                        }
                        if (!found)
                            return null;
                        string text = TakeText(Core.BNTagGetData(tag));
                        if (facts.TryGetValue(key, out var saved) && saved.Text.Length == 4) {
                            nint type = Core.BNTagGetType(tag);
                            try {
                                fact.Text = [text, TakeText(Core.BNTagTypeGetName(type)), saved.Text[2],
                                    TakeText(Core.BNTagTypeGetId(type))];
                            } finally {
                                Core.BNFreeTagType(type);
                            }
                        } else {
                            fact.Text = [text];
                        }
                    } finally {
                        Core.BNFreeTag(tag);
                    }
                    break;
                }
                case Kind.Metadata: {
                    nint metadata = Core.BNBinaryViewQueryMetadata(View, id);
                    if (metadata == 0)
                        return null;
                    try {
                        // A user can replace a private raw cache with another
                        // metadata kind. Preserve it as a distinct current value.
                        if (Core.BNMetadataIsRaw(metadata) != 0)
                            fact.Bytes = Raw(metadata);
                        else
                            fact.Text = ["nonraw"];
                    } finally {
                        Core.BNFreeMetadata(metadata);
                    }
                    break;
                }
                case Kind.Field: {
                    if (!facts.TryGetValue(key, out var saved))
                        return null;
                    fact.Text = saved.Text;
                    var name = NativeName(saved.Text, out byte[] buffer);
                    byte** parts = stackalloc byte*[saved.Text.Length];
                    fixed (byte* bytes = buffer) {
                        FillName(&name, bytes, parts, saved.Text);
                        nuint count = 0;
                        var references = Core.BNGetCodeReferencesForTypeField(View, &name, key.Target, &count, 0, 0);
                        bool found = false;
                        try {
                            for (nuint i = 0; i < count; ++i) {
                                ref readonly var reference = ref references[i];
                                if (reference.Address == address && reference.Size == saved.Size
                                    && Core.BNGetFunctionStart(reference.Function) == imageBase + FieldFunction(key)) {
                                    found = true;
                                    break;
                                }
                            }
                        } finally {
                            Core.BNFreeTypeFieldReferences(references, count);
                        }
                        if (!found)
                            return null;
                    }
                    fact.Size = saved.Size;
                    break;
                }
            }
        }
        return fact;
    }

    private static SymbolSnapshot SymbolState(nint symbol) {
        var nameSpace = Core.BNGetSymbolNameSpace(symbol);
        try {
            return new SymbolSnapshot {
                Kind = Core.BNGetSymbolType(symbol),
                ShortName = TakeText(Core.BNGetSymbolShortName(symbol)),
                FullName = TakeText(Core.BNGetSymbolFullName(symbol)),
                RawName = TakeText(Core.BNGetSymbolRawName(symbol)),
                Binding = Core.BNGetSymbolBinding(symbol),
                Ordinal = Core.BNGetSymbolOrdinal(symbol),
                Join = Text(nameSpace.Join),
                Namespace = Name(nameSpace)
            };
        } finally {
            Core.BNFreeNameSpace(&nameSpace);
        }
    }

    private static byte[] AbiMetadata(nint type) {
        using var output = new MemoryStream();
        using var writer = new BinaryWriter(output, Encoding.UTF8, leaveOpen: true);
        ReturnValue result = Core.BNGetTypeReturnValue(type);
        try {
            writer.Write(result.TypeConfidence);
            writer.Write(result.DefaultLocation);
            writer.Write(result.LocationConfidence);
            WriteLocation(writer, result.Location);
        } finally {
            Core.BNFreeType(result.Type);
            Core.BNFreeValueLocation(&result.Location);
        }
        nuint count = 0;
        var parameters = Core.BNGetTypeParameters(type, &count);
        try {
            writer.Write((ulong)count);
            for (nuint i = 0; i < count; ++i) {
                writer.Write(Text(parameters[i].Name));
                writer.Write(parameters[i].TypeConfidence);
                writer.Write(parameters[i].LocationSource);
                WriteLocation(writer, parameters[i].Location);
            }
        } finally {
            Core.BNFreeTypeParameterList(parameters, count);
        }
        var convention = Core.BNGetTypeCallingConvention(type);
        writer.Write(convention.Confidence);
        writer.Write(convention.Convention == 0 ? "" : TakeText(Core.BNGetCallingConventionName(convention.Convention)));
        if (convention.Convention != 0)
            Core.BNFreeCallingConvention(convention.Convention);
        var stack = Core.BNGetTypeStackAdjustment(type);
        writer.Write(stack.Value);
        writer.Write(stack.Confidence);
        foreach (var value in new[] { Core.BNTypeHasVariableArguments(type), Core.BNFunctionTypeCanReturn(type), Core.BNIsTypePure(type) }) {
            writer.Write(value.Value);
            writer.Write(value.Confidence);
        }
        return output.ToArray();
    }

    private static void WriteLocation(BinaryWriter writer, ValueLocation location) {
        writer.Write((ulong)location.Count);
        writer.Write(location.Indirect);
        writer.Write(location.ReturnedPointerValid);
        if (location.ReturnedPointerValid != 0)
            WriteVariable(writer, location.ReturnedPointer);
        var components = new ReadOnlySpan<ValueLocationComponent>((void*)location.Components, checked((int)location.Count));
        foreach (ref readonly var component in components) {
            WriteVariable(writer, component.Variable);
            writer.Write(component.Offset);
            writer.Write(component.SizeValid);
            if (component.SizeValid != 0)
                writer.Write(component.Size);
        }
    }

    private static void WriteVariable(BinaryWriter writer, Variable variable) {
        writer.Write(variable.Source);
        writer.Write(variable.Index);
        writer.Write(variable.Storage);
    }

    private static bool Equal(Fact? current, Fact expected) => current != null
        && current.Automatic == expected.Automatic
        && current.Confidence == expected.Confidence
        && EqualSymbol(current.Symbol, expected.Symbol)
        && current.Text.AsSpan().SequenceEqual(expected.Text)
        && current.Bytes.AsSpan().SequenceEqual(expected.Bytes)
        && current.Size == expected.Size
        && (current.Type == expected.Type || (current.Type != 0 && expected.Type != 0 && Core.BNTypesEqual(current.Type, expected.Type) != 0));

    private static bool EqualSymbol(SymbolSnapshot? current, SymbolSnapshot? expected) => current == expected
        || (current != null && expected != null
            && current.Kind == expected.Kind
            && current.ShortName == expected.ShortName
            && current.FullName == expected.FullName
            && current.RawName == expected.RawName
            && current.Binding == expected.Binding
            && current.Ordinal == expected.Ordinal
            && current.Join == expected.Join
            && current.Namespace.AsSpan().SequenceEqual(expected.Namespace));

    private bool Accept(Key key, Fact? current, bool acquire) {
        cancellationToken.ThrowIfCancellationRequested();

        if (facts.TryGetValue(key, out var previous)) {
            previous.Seen = true;
            if (!previous.Excluded && Equal(current, previous)) {
                IndexTag(previous);
                return true;
            }
        } else if (acquire) {
            return true;
        }

        facts.TryGetValue(key, out var rejected);
        facts[key] = Exclusion(key, rejected, current == null);
        IndexTag(facts[key]);
        return false;
    }

    private static Fact Exclusion(Key key, Fact? previous, bool deleted) {
        string[] text = [];
        if (key.Kind == Kind.Tag) {
            if (previous?.Text.Length == 4)
                text = [previous.Text[1], previous.Text[2], deleted ? "deleted" : "edited"];
            else if (previous?.Excluded == true && previous.Text.Length == 3)
                text = [previous.Text[0], previous.Text[1], deleted ? "deleted" : "edited"];
        } else if (key.Kind == Kind.Metadata && key.Id == "aot-atlas:apply-input") {
            if (previous?.Bytes.Length == 73 && previous.Bytes.AsSpan(0, 8).SequenceEqual("ATINPUT1"u8)
                && previous.Bytes[72] <= (byte)MapFormat.Metadata)
                text = [previous.Bytes[72].ToString()];
            else if (previous?.Excluded == true && previous.Text.Length == 1)
                text = previous.Text;
        }
        return new Fact { Key = key, Seen = true, Excluded = true, Text = text };
    }

    private void Record(Fact? before, Fact after) {
        cancellationToken.ThrowIfCancellationRequested();

        after.Seen = true;
        changes.Add((before, after));
        facts[after.Key] = after;
        IndexTag(after);
        if (after.Key.Kind == Kind.Tag)
            tagKeys[after.Key.Id] = after.Key;
    }

    internal bool OwnsSymbol(ulong address, nint symbol) {
        var key = new Key(Kind.Symbol, address - imageBase);
        if (!facts.TryGetValue(key, out var fact) || fact.Excluded)
            return false;

        var current = new Fact { Key = key, Symbol = SymbolState(symbol), Automatic = Core.BNIsSymbolAutoDefined(symbol) != 0 };
        return Equal(current, fact);
    }

    internal bool OwnsVariable(ulong address, nint type, byte confidence) {
        var key = new Key(Kind.Variable, address - imageBase);
        return facts.TryGetValue(key, out var fact) && !fact.Excluded
            && fact.Confidence == confidence
            && Core.BNTypesEqual(type, fact.Type) != 0;
    }

    internal void ExcludeSymbol(ulong address) =>
        Exclude(new Key(Kind.Symbol, address - imageBase));

    internal void VisitSymbol(ulong address) {
        if (facts.TryGetValue(new Key(Kind.Symbol, address - imageBase), out var fact))
            fact.Seen = true;
    }

    internal void ExcludeVariable(ulong address) =>
        Exclude(new Key(Kind.Variable, address - imageBase));

    private void Exclude(Key key) {
        facts[key] = new Fact { Key = key, Seen = true, Excluded = true };
    }

    internal void ReserveTags(int count) {
        facts.EnsureCapacity(checked(facts.Count + count));
        tagKeys.EnsureCapacity(checked(tagKeys.Count + count));
    }

    internal QualifiedName DefineType(byte* id, QualifiedName* name, nint type) {
        var key = new Key(Kind.Type, Id: Text(id));
        Fact? before = Capture(key);

        if (!Accept(key, before, before == null || before.Automatic)) {
            var preserved = Core.BNGetAnalysisTypeNameById(View, id);
            if (preserved.Count != 0)
                return preserved;

            Core.BNFreeQualifiedName(&preserved);
            return new QualifiedName {
                Names = Core.BNAllocStringList(name->Names, name->Count),
                Join = Core.BNAllocString(name->Join),
                Count = name->Count
            };
        }

        var after = new Fact { Key = key, Type = Retain(type), Text = Name(*name), Automatic = true,
            Bytes = Core.BNGetTypeClass(type) == 5 && Core.BNIsTypeSigned(type).Value != 0 ? [1] : [] };
        Record(before, after);

        var actual = Core.DefineType(View, id, name, type);
        if (actual.Count == 0) {
            Core.BNFreeQualifiedName(&actual);
            throw new IOException("Binary Ninja did not return the applied annotation type name.");
        }

        after.Text = Name(actual);
        return actual;
    }

    internal nint CreateTypeReference(byte* id, QualifiedName* name, nint type) {
        var key = new Key(Kind.Type, Id: Text(id));
        if (!facts.TryGetValue(key, out var fact) || !fact.Excluded)
            return Core.CreateTypeReference(id, name, type);

        nint preserved = Core.BNGetAnalysisTypeById(View, id);
        if (preserved == 0)
            return Core.CreateTypeReference(id, name, type);

        try {
            return Core.CreateTypeReference(id, name, preserved);
        } finally {
            Core.BNFreeType(preserved);
        }
    }

    internal void DefineSymbol(nint symbol, nint previous = -1) {
        ulong address = Core.BNGetSymbolAddress(symbol);
        var key = new Key(Kind.Symbol, address - imageBase);
        Fact? before = previous == -1
            ? Capture(key)
            : previous == 0 ? null : new Fact {
                Key = key,
                Symbol = SymbolState(previous),
                Automatic = Core.BNIsSymbolAutoDefined(previous) != 0
            };
        if (!Accept(key, before, before == null || before.Automatic))
            return;

        Record(before, new Fact { Key = key, Symbol = SymbolState(symbol) });

        Core.DefineSymbol(View, symbol);
    }

    internal void DefineVariable(ulong address, TypeConfidence* type) {
        var key = new Key(Kind.Variable, address - imageBase);
        Fact? before = Capture(key);
        // DataVariables preserves every pre-apply user variable. A newly
        // materialised user void came from a reference in this apply.
        if (before is { Automatic: false, Type: not 0 } && Core.BNGetTypeClass(before.Type) == 0) {
            Core.BNUndefineUserDataVariable(View, address);
            before = null;
        }
        if (!Accept(key, before, before == null || before.Automatic))
            return;

        Record(before, new Fact { Key = key, Type = Retain(type->Type), Confidence = type->Confidence });

        Core.DefineVariable(View, address, type);
    }

    internal void AddReference(ulong from, ulong to) {
        var key = new Key(Kind.Reference, from - imageBase, to - imageBase);
        Fact? before = Capture(key);
        if (!Accept(key, before, before == null))
            return;

        // The native getter merges user and automatic references. An existing
        // edge may therefore survive an analyst's deletion of its user layer.
        if (before != null)
            return;

        Record(before, new Fact { Key = key });

        Core.AddReference(View, from, to);
    }

    internal void VisitFunction(ulong address) {
        if (facts.TryGetValue(new Key(Kind.Function, address - imageBase), out var fact))
            fact.Seen = true;
    }

    internal nint AddFunction(nint selectedPlatform, ulong address, byte auto, nint type) {
        var key = new Key(Kind.Function, address - imageBase);
        Fact? before = Capture(key);
        if (before != null)
            return Core.AddFunction(View, selectedPlatform, address, auto, type);

        Record(null, new Fact { Key = key, Automatic = true });

        return Core.AddFunction(View, selectedPlatform, address, auto, type);
    }

    internal void ApplyFunctionType(nint function, nint type) {
        var key = new Key(Kind.Abi, Core.BNGetFunctionStart(function) - imageBase);
        Fact? before = Capture(key);
        if (!Accept(key, before, before != null && before.Automatic))
            return;

        nint prior = facts.TryGetValue(key, out var old) ? old.PriorType : before!.Type;
        var after = new Fact {
            Key = key,
            Automatic = true,
            Type = Retain(type),
            PriorType = prior,
            Bytes = AbiMetadata(type)
        };
        Record(before, after);

        Core.BNSetFunctionAutoType(function, type);
        Core.ApplyFunctionType(function, type);

        // The host merges confidence and existing automatic ABI properties.
        // Record the resulting contract, rather than assuming it equals the request.
        var observed = Capture(key);
        if (observed == null)
            throw new IOException("Binary Ninja did not return the applied function ABI.");

        after.Type = observed.Type;
        after.Bytes = observed.Bytes;
    }

    internal bool ContainsTag(nint tag) {
        var fact = TagFact(tag);
        if (fact == null || fact.Excluded)
            return false;

        var current = Capture(fact.Key);
        return Accept(fact.Key, current, false);
    }

    internal bool CanCreateTag(nint tagType, ulong address, bool data, string slot) {
        var site = new TagSite(address - imageBase, data ? 1UL : 0UL, TagType(tagType).Category, slot);
        if (!tagSites.TryGetValue(site, out var fact))
            return true;

        if (fact.Excluded && fact.Text[2] == "deleted")
            return false;

        Fact? current = Capture(fact.Key);
        if (fact.Excluded && current != null)
            return true;

        if (!Equal(current, fact)) {
            facts[fact.Key] = Exclusion(fact.Key, fact, current == null);
            IndexTag(facts[fact.Key]);
            return current != null;
        }

        return true;
    }

    private TagTypeIdentity TagType(nint type) {
        if (!tagTypes.TryGetValue(type, out var identity)) {
            identity = new(TakeText(Core.BNTagTypeGetName(type)), TakeText(Core.BNTagTypeGetId(type)));
            tagTypes.Add(type, identity);
        }

        return identity;
    }

    private static TagSite TagLocation(Fact fact) {
        int identity = fact.Excluded ? 0 : 1;
        return new(fact.Key.Address, fact.Key.Target, fact.Text[identity], fact.Text[identity + 1]);
    }

    private void IndexTag(Fact fact) {
        // Active tag receipts hold data/category/slot/native type ID. Exclusions
        // keep category/slot/deleted-or-edited so a new native ID cannot erase intent.
        if (fact.Key.Kind != Kind.Tag || fact.Text.Length != (fact.Excluded ? 3 : 4))
            return;

        var site = TagLocation(fact);
        if (tagSites.TryGetValue(site, out var prior)) {
            if (prior.Excluded && prior.Text[2] == "deleted" && !(fact.Excluded && fact.Text[2] == "deleted"))
                return;
            if (!prior.Excluded && fact.Excluded && fact.Text[2] == "edited")
                return;
        }

        tagSites[site] = fact;
    }

    private void RemoveTagIndex(Fact fact) {
        if (fact.Key.Kind != Kind.Tag || fact.Text.Length != (fact.Excluded ? 3 : 4))
            return;

        var site = TagLocation(fact);
        if (tagSites.TryGetValue(site, out var indexed) && indexed == fact)
            tagSites.Remove(site);
    }

    private void UpgradeTagIdentity(Fact fact) {
        byte[] id = Encoding.UTF8.GetBytes(fact.Key.Id + '\0');
        nint tag;
        fixed (byte* value = id)
            tag = Core.BNGetTag(View, value);
        if (tag == 0) {
            byte[] text = Encoding.UTF8.GetBytes(fact.Text[0]);
            string? category = null;
            string slot = "";
            if (fact.Key.Target == 0 && MethodAnnotations.TryTagKey(text, out ulong method)) {
                category = "AOT Atlas methods";
                slot = method.ToString("X");
            } else if (DispatchAnnotations.TryTagKey(text, out ulong dispatch)) {
                category = "AOT Atlas dispatch";
                slot = dispatch.ToString("X");
            }

            if (category != null) {
                fact.Excluded = true;
                fact.Text = [category, slot, "deleted"];
            } else {
                LegacyTagIdentityMissing = true;
            }

            return;
        }

        try {
            nint tagType = Core.BNTagGetType(tag);
            try {
                byte[] text = Encoding.UTF8.GetBytes(fact.Text[0]);
                string slot = MethodAnnotations.TryTagKey(text, out ulong method) ? method.ToString("X")
                    : DispatchAnnotations.TryTagKey(text, out ulong dispatch) ? dispatch.ToString("X") : "";
                var identity = TagType(tagType);
                fact.Text = [fact.Text[0], identity.Category, slot, identity.NativeId];
            } finally {
                Core.BNFreeTagType(tagType);
            }
        } finally {
            Core.BNFreeTag(tag);
        }
    }

    internal void RegisterTag(nint tag, ulong address, bool data, string slot = "") {
        registeredTags.Add(Core.BNNewTagReference(tag));

        Core.BNAddTag(View, tag, 1);

        var key = new Key(Kind.Tag, address - imageBase, data ? 1UL : 0UL, TakeText(Core.BNTagGetId(tag)));
        retiredTags.Add(key.Id);
        nint tagType = Core.BNTagGetType(tag);
        try {
            var identity = TagType(tagType);
            Record(null, new Fact { Key = key, Text = [TakeText(Core.BNTagGetData(tag)),
                identity.Category, slot, identity.NativeId] });
        } finally {
            Core.BNFreeTagType(tagType);
        }
    }

    private Fact? TagFact(nint tag) {
        string id = TakeText(Core.BNTagGetId(tag));
        return tagKeys.TryGetValue(id, out var key) && facts.TryGetValue(key, out var fact) ? fact : null;
    }

    internal void SetTagData(nint tag, byte* text) {
        var previous = TagFact(tag);
        if (previous == null)
            return;

        Fact? before = Capture(previous.Key);
        if (!Accept(previous.Key, before, false))
            return;

        Record(before, new Fact { Key = previous.Key, Text = previous.Text.Length == 4
            ? [Text(text), previous.Text[1], previous.Text[2], previous.Text[3]] : [Text(text)] });

        Core.SetTagData(tag, text);
    }

    internal void ForgetTag(nint tag) {
        var fact = TagFact(tag);
        if (fact != null) {
            changes.Add((fact, new Fact { Key = fact.Key, Excluded = true }));
            facts.Remove(fact.Key);
            RemoveTagIndex(fact);
            tagKeys.Remove(fact.Key.Id);
        }
    }

    internal void RetireTag(nint tag) => retiredTags.Add(TakeText(Core.BNTagGetId(tag)));

    internal bool MetadataTrusted(string name, ReadOnlySpan<byte> bytes) {
        var key = new Key(Kind.Metadata, Id: name);
        return facts.TryGetValue(key, out var previous) && !previous.Excluded && previous.Bytes.AsSpan().SequenceEqual(bytes);
    }

    internal bool MetadataTrusted(string name) {
        var key = new Key(Kind.Metadata, Id: name);
        if (!facts.TryGetValue(key, out var previous) || previous.Excluded)
            return false;

        byte[] identifier = Encoding.UTF8.GetBytes(name + '\0');
        nint record;
        fixed (byte* id = identifier)
            record = Core.BNBinaryViewQueryMetadata(View, id);
        if (record == 0)
            return false;

        byte* data = null;
        try {
            if (Core.BNMetadataIsRaw(record) == 0)
                return false;
            nuint length = 0;
            data = Core.BNMetadataGetRaw(record, &length);
            return MetadataTrusted(name, new ReadOnlySpan<byte>(data, checked((int)length)));
        } finally {
            if (data != null)
                Core.BNFreeMetadataRaw(data);
            Core.BNFreeMetadata(record);
        }
    }

    internal bool TryInputFormat(out MapFormat format) {
        format = MapFormat.Auto;
        if (!facts.TryGetValue(new Key(Kind.Metadata, Id: "aot-atlas:apply-input"), out var input))
            return false;

        if (input.Excluded) {
            if (input.Text.Length != 1)
                return false;
            format = (MapFormat)byte.Parse(input.Text[0]);
            return true;
        }

        if (input.Bytes.Length != 73 || !input.Bytes.AsSpan(0, 8).SequenceEqual("ATINPUT1"u8)
            || input.Bytes[72] > (byte)MapFormat.Metadata)
            return false;
        format = (MapFormat)input.Bytes[72];
        return true;
    }

    internal void RememberInputFormat(MapFormat format) {
        var key = new Key(Kind.Metadata, Id: "aot-atlas:apply-input");
        if (facts.TryGetValue(key, out var input) && input.Excluded)
            input.Text = [((byte)format).ToString()];
    }

    private void RecoverEnumSignedness() {
        if (!facts.TryGetValue(new Key(Kind.Metadata, Id: "aot-atlas:signed-enums"), out var saved) || saved.Excluded)
            return;
        var bytes = saved.Bytes.AsSpan();
        if (bytes.Length < 8 || (bytes.Length - 8) % 8 != 0 || !bytes[..8].SequenceEqual("ATENUM01"u8))
            throw new InvalidDataException("The owned Atlas signed-enum record is invalid.");
        for (int position = 8; position < bytes.Length; position += 8) {
            var entry = bytes.Slice(position, 8);
            if (entry[4] > 1 || entry[5] is not (1 or 2 or 4 or 8) || entry[6] != 0 || entry[7] != 0)
                throw new InvalidDataException("The owned Atlas signed-enum type entry is invalid.");
            uint offset = BinaryPrimitives.ReadUInt32LittleEndian(entry);
            string id = entry[4] == 0 ? $"aot-atlas:enum:v1:{offset:X8}" : $"aot-atlas:runtime-type:v1:{offset:X8}";
            if (facts.TryGetValue(new Key(Kind.Type, Id: id), out var fact) && !fact.Excluded
                && Core.BNGetTypeClass(fact.Type) == 5 && Core.BNGetTypeWidth(fact.Type) == entry[5])
                fact.Bytes = [1];
        }
    }

    internal int NormalizeSignedEnums() {
        int count = 0;
        foreach (var expected in facts.Values) {
            cancellationToken.ThrowIfCancellationRequested();
            if (expected.Key.Kind != Kind.Type || expected.Excluded || expected.Bytes.Length != 1)
                continue;

            if (Core.BNIsTypeSigned(expected.Type).Value == 0) {
                expected.Type = EnumTypes.SignedCopy(expected.Type);
                types.Add(expected.Type);
            }

            var before = Capture(expected.Key);
            if (before == null || !before.Automatic || !before.Text.AsSpan().SequenceEqual(expected.Text)
                || Core.BNGetTypeClass(before.Type) != 5 || Core.BNIsTypeSigned(before.Type).Value != 0)
                continue;

            nint replacement = EnumTypes.SignedCopy(before.Type);
            try {
                if (Core.BNTypesEqual(replacement, expected.Type) == 0)
                    continue;
                var after = new Fact { Key = expected.Key, Type = Retain(replacement), Text = expected.Text,
                    Automatic = true, Bytes = [1] };
                changes.Add((before, after));
                byte[] identifier = Encoding.UTF8.GetBytes(expected.Key.Id + '\0');
                var name = NativeName(expected.Text, out byte[] buffer);
                nint[] parts = new nint[expected.Text.Length];
                fixed (byte* id = identifier)
                fixed (nint* names = parts)
                fixed (byte* bytes = buffer) {
                    FillName(&name, bytes, (byte**)names, expected.Text);
                    var actual = Core.DefineType(View, id, &name, replacement);
                    Core.BNFreeQualifiedName(&actual);
                }
                ++count;
            } finally {
                Core.BNFreeType(replacement);
            }
        }
        return count;
    }

    internal void CompleteRepairs() {
        Save();
        complete = true;
    }

    internal void Suspend() {
        if (Current != this || changes.Count != 0)
            throw new InvalidOperationException("Only an unchanged ownership snapshot can be suspended.");
        Current = null;
    }

    internal bool TryResume(nint view) {
        if (disposed || generation == null || nativeIdentityRecovered || view != View
            || Core.BNGetImageBase(view) != imageBase)
            return false;
        nint currentPlatform = Core.BNGetDefaultPlatform(view);
        bool samePlatform = currentPlatform == platform;
        if (currentPlatform != 0)
            Core.BNFreePlatform(currentPlatform);
        if (!samePlatform)
            return false;
        nint record;
        fixed (byte* key = "aot-atlas:owned-annotations\0"u8)
            record = Core.BNBinaryViewQueryMetadata(view, key);
        if (record == 0)
            return false;
        byte* data = null;
        try {
            if (Core.BNMetadataIsRaw(record) == 0)
                return false;
            nuint length = 0;
            data = Core.BNMetadataGetRaw(record, &length);
            if (!new ReadOnlySpan<byte>(data, checked((int)length)).SequenceEqual(generation))
                return false;
            if (Current != null)
                throw new InvalidOperationException("An Atlas annotation operation is already active on this thread.");
            Current = this;
            return true;
        } finally {
            if (data != null)
                Core.BNFreeMetadataRaw(data);
            Core.BNFreeMetadata(record);
        }
    }

    internal void StoreMetadata(byte* id, nint metadata, byte flags) {
        var key = new Key(Kind.Metadata, Id: Text(id));
        Fact? before = Capture(key);
        if (!Accept(key, before, before == null))
            return;

        Record(before, new Fact { Key = key, Bytes = Raw(metadata) });

        Core.StoreMetadataRaw(View, id, metadata, flags);
    }

    internal bool AddFieldReference(nint function, nint architecture, ulong address, QualifiedName* name, ulong offset, nuint size) {
        string[] text = Name(*name);
        string identity = (Core.BNGetFunctionStart(function) - imageBase).ToString("X") + ":" + size.ToString("X") + ":" + NameKey(text);
        var key = new Key(Kind.Field, address - imageBase, offset, identity);
        var desired = new Fact { Key = key, Text = text, Size = size };
        bool existed = facts.TryGetValue(key, out var previous);
        if (!existed)
            facts.Add(key, desired);

        Fact? before = Capture(key);
        if (!existed)
            facts.Remove(key);

        if (!Accept(key, before, before == null))
            return false;

        if (before != null)
            return true;

        Record(before, desired);

        Core.AddFieldReference(function, architecture, address, name, offset, size);
        return true;
    }

    internal void RetractFields() {
        var fields = facts.Values.Where(fact => fact.Key.Kind == Kind.Field && !fact.Excluded).ToArray();
        foreach (var fact in fields) {
            cancellationToken.ThrowIfCancellationRequested();

            Fact? current = Capture(fact.Key);
            if (Equal(current, fact)) {
                changes.Add((fact, new Fact { Key = fact.Key, Excluded = true }));
                Restore(null, fact, retract: true);
                facts.Remove(fact.Key);
            } else {
                facts[fact.Key] = new Fact { Key = fact.Key, Excluded = true };
            }
        }
    }

    internal OwnedCounts Complete() {
        // References and ABI must disappear before types; generated tags and
        // symbols must disappear before deciding whether a function has user work.
        Kind[] order = fieldsOnly
            ? [Kind.Field]
            : [Kind.Tag, Kind.Reference, Kind.Abi, Kind.Variable, Kind.Symbol, Kind.Metadata, Kind.Function, Kind.Type];
        foreach (Kind kind in order) {
            if (kind == Kind.Type)
                RetainReferencedTypes();
            var stale = facts.Values.Where(fact => fact.Key.Kind == kind && !fact.Seen && !fact.Excluded).ToArray();
            foreach (var fact in stale) {
                cancellationToken.ThrowIfCancellationRequested();

                if (kind == Kind.Function
                    && facts.TryGetValue(new Key(Kind.Abi, fact.Key.Address), out var abi)
                    && abi.Excluded) {
                    fact.Seen = true;
                    continue;
                }
                Fact? current = Capture(fact.Key);
                if (Equal(current, fact)) {
                    changes.Add((fact, new Fact { Key = fact.Key, Excluded = true }));
                    Restore(null, fact, retract: true);
                    facts.Remove(fact.Key);
                    RemoveTagIndex(fact);
                } else {
                    facts[fact.Key] = Exclusion(fact.Key, fact, current == null);
                    IndexTag(facts[fact.Key]);
                }
            }
        }
        cancellationToken.ThrowIfCancellationRequested();
        OwnedCounts owned = Save();
        complete = true;
        CleanRetiredTags();
        return owned;
    }

    private void CleanRetiredTags() {
        nuint count = 0;
        var references = Core.BNGetAllTagReferences(View, &count);
        try {
            var attached = new HashSet<string>();
            for (nuint i = 0; i < count; ++i)
                attached.Add(TakeText(Core.BNTagGetId(references[i].Tag)));
            foreach (string identity in retiredTags) {
                if (attached.Contains(identity))
                    continue;
                byte[] identifier = Encoding.UTF8.GetBytes(identity + '\0');
                fixed (byte* id = identifier) {
                    nint tag = Core.BNGetTag(View, id);
                    if (tag != 0) {
                        Core.RemoveTag(View, tag, 1);
                        Core.BNFreeTag(tag);
                    }
                }
            }
            var referenced = new HashSet<nint>();
            for (nuint i = 0; i < count; ++i)
                referenced.Add(references[i].Tag);
            foreach (nint tag in registeredTags) {
                if (!referenced.Contains(tag))
                    Core.RemoveTag(View, tag, 1);
            }
        } finally {
            Core.BNFreeTagReferences(references, count);
        }
    }

    private static string NameKey(string[] parts) {
        var text = new StringBuilder();
        foreach (string part in parts)
            text.Append(part.Length).Append(':').Append(part);
        return text.ToString();
    }

    private static ulong FieldFunction(Key key) => Convert.ToUInt64(key.Id[..key.Id.IndexOf(':')], 16);

    private void RetainReferencedTypes() {
        var stale = facts.Values.Where(fact => fact.Key.Kind == Kind.Type && !fact.Seen && !fact.Excluded).ToArray();
        var byName = new Dictionary<string, int>(stale.Length);
        var dependencies = new List<int>[stale.Length];
        var retained = new HashSet<int>();
        int maxParts = 0;
        for (int i = 0; i < stale.Length; ++i) {
            byName.Add(NameKey(stale[i].Text), i);
            dependencies[i] = [];
            maxParts = Math.Max(maxParts, stale[i].Text.Length);
        }

        byte** parts = stackalloc byte*[maxParts];
        for (int i = 0; i < stale.Length; ++i) {
            var name = NativeName(stale[i].Text, out byte[] buffer);
            fixed (byte* bytes = buffer) {
                FillName(&name, bytes, parts, stale[i].Text);
                nuint codeCount = 0;
                nuint dataCount = 0;
                nuint typeCount = 0;
                var code = Core.BNGetCodeReferencesForType(View, &name, &codeCount, 0, 0);
                var data = Core.BNGetDataReferencesForType(View, &name, &dataCount, 0, 0);
                var references = Core.BNGetTypeReferencesForType(View, &name, &typeCount, 0, 0);
                try {
                    if (codeCount != 0 || dataCount != 0)
                        retained.Add(i);
                    for (nuint j = 0; j < typeCount; ++j) {
                        string source = NameKey(Name(references[j].Name));
                        if (byName.TryGetValue(source, out int owner))
                            dependencies[owner].Add(i);
                        else
                            retained.Add(i);
                    }
                } finally {
                    Core.BNFreeCodeReferences(code, codeCount);
                    Core.BNFreeDataReferences(data);
                    Core.BNFreeTypeReferences(references, typeCount);
                }
            }
        }

        // Delete an unreferenced stale component together. A surviving analyst
        // annotation keeps the types it depends on, including recursive types.
        var pending = new Queue<int>(retained);
        while (pending.TryDequeue(out int index)) {
            stale[index].Seen = true;
            foreach (int target in dependencies[index]) {
                if (retained.Add(target))
                    pending.Enqueue(target);
            }
        }
    }

    private void Restore(Fact? before, Fact after, bool retract) {
        ulong address = imageBase + after.Key.Address;
        byte[] identifier = Encoding.UTF8.GetBytes(after.Key.Id + '\0');
        fixed (byte* id = identifier) {
            switch (after.Key.Kind) {
                case Kind.Type: {
                    if (before == null) {
                        Core.BNUndefineAnalysisType(View, id);
                    } else {
                        var name = NativeName(before.Text, out byte[] buffer);
                        byte** parts = stackalloc byte*[before.Text.Length];
                        fixed (byte* bytes = buffer) {
                            FillName(&name, bytes, parts, before.Text);
                            var actual = Core.DefineType(View, id, &name, before.Type);
                            Core.BNFreeQualifiedName(&actual);
                        }
                    }
                    break;
                }
                case Kind.Symbol: {
                    nint symbol = Core.BNGetSymbolByAddress(View, address, 0);
                    if (symbol != 0) {
                        Core.BNUndefineUserSymbol(View, symbol);
                        Core.BNFreeSymbol(symbol);
                    }
                    if (before != null && !before.Automatic) {
                        var state = before.Symbol!;
                        byte[] shortName = Encoding.UTF8.GetBytes(state.ShortName + '\0');
                        byte[] fullName = Encoding.UTF8.GetBytes(state.FullName + '\0');
                        byte[] rawName = Encoding.UTF8.GetBytes(state.RawName + '\0');
                        fixed (byte* shortText = shortName)
                        fixed (byte* fullText = fullName)
                        fixed (byte* rawText = rawName) {
                            var nameSpace = NativeName(state.Namespace, out byte[] namespaceBuffer, state.Join);
                            byte** parts = stackalloc byte*[state.Namespace.Length];
                            fixed (byte* namespaceBytes = namespaceBuffer) {
                                FillName(&nameSpace, namespaceBytes, parts, state.Namespace);
                                symbol = Core.BNCreateSymbol(state.Kind, shortText, fullText, rawText, address,
                                    state.Binding, nameSpace.Count == 0 ? 0 : (nint)(&nameSpace), state.Ordinal);
                                Core.DefineSymbol(View, symbol);
                                Core.BNFreeSymbol(symbol);
                            }
                        }
                    }
                    break;
                }
                case Kind.Variable: {
                    Core.BNUndefineUserDataVariable(View, address);
                    if (before != null && !before.Automatic) {
                        var confidence = new TypeConfidence(before.Type) { Confidence = before.Confidence };
                        Core.DefineVariable(View, address, &confidence);
                    }
                    break;
                }
                case Kind.Reference:
                    if (before == null)
                        Core.BNRemoveUserDataReference(View, address, imageBase + after.Key.Target);
                    else
                        Core.AddReference(View, address, imageBase + after.Key.Target);
                    break;
                case Kind.Abi: {
                    nint function = Core.GetFunction(View, platform, address);
                    if (function == 0)
                        break;
                    nint type = retract ? after.PriorType : before?.Type ?? 0;
                    Core.BNSetFunctionAutoType(function, type);
                    Core.BNFreeFunction(function);
                    break;
                }
                case Kind.Function: {
                    nint function = Core.GetFunction(View, platform, address);
                    if (before == null && function != 0) {
                        Core.BNRemoveAnalysisFunction(View, function, 1);
                    } else if (before != null && function == 0) {
                        function = Core.AddFunction(View, platform, address, 0, 0);
                    }
                    if (function != 0)
                        Core.BNFreeFunction(function);
                    break;
                }
                case Kind.Tag: {
                    nint tag = Core.BNGetTag(View, id);
                    if (tag == 0)
                        break;
                    if (before != null) {
                        byte[] text = Encoding.UTF8.GetBytes(before.Text[0] + '\0');
                        fixed (byte* value = text)
                            Core.SetTagData(tag, value);
                        if (after.Excluded && before.Key.Target == 1) {
                            Core.AddDataTag(View, imageBase + before.Key.Address, tag);
                        } else if (after.Excluded) {
                            nint function = Core.GetFunction(View, platform, imageBase + before.Key.Address);
                            if (function != 0) {
                                Core.AddFunctionTag(function, tag);
                                Core.BNFreeFunction(function);
                            }
                        }
                    } else {
                        if (after.Key.Target == 1) {
                            Core.BNRemoveUserDataTag(View, address, tag);
                        } else {
                            nint function = Core.GetFunction(View, platform, address);
                            if (function != 0) {
                                Core.BNRemoveUserFunctionTag(function, tag);
                                Core.BNFreeFunction(function);
                            }
                        }
                        retiredTags.Add(after.Key.Id);
                    }
                    Core.BNFreeTag(tag);
                    break;
                }
                case Kind.Metadata: {
                    if (before == null) {
                        Core.BNBinaryViewRemoveMetadata(View, id);
                    } else {
                        fixed (byte* value = before.Bytes) {
                            nint metadata = Core.BNCreateMetadataRawData(value, (nuint)before.Bytes.Length);
                            Core.StoreMetadataRaw(View, id, metadata, 3);
                            Core.BNFreeMetadata(metadata);
                        }
                    }
                    break;
                }
                case Kind.Field: {
                    var fact = before ?? after;
                    var name = NativeName(fact.Text, out byte[] buffer);
                    byte** parts = stackalloc byte*[fact.Text.Length];
                    nint function = Core.GetFunction(View, platform, imageBase + FieldFunction(fact.Key));
                    if (function == 0)
                        break;
                    try {
                        fixed (byte* bytes = buffer) {
                            FillName(&name, bytes, parts, fact.Text);
                            nint architecture = Core.BNGetPlatformArchitecture(platform);
                            if (before == null)
                                Core.BNRemoveUserTypeFieldReference(function, architecture, address, &name, fact.Key.Target, (nuint)fact.Size);
                            else
                                Core.AddFieldReference(function, architecture, address, &name, fact.Key.Target, (nuint)fact.Size);
                        }
                    } finally {
                        Core.BNFreeFunction(function);
                    }
                    break;
                }
            }
        }
    }

    public void Dispose() {
        if (disposed)
            return;
        try {
            if (!complete && (changes.Count != 0 || retiredTags.Count != 0 || registeredTags.Count != 0)) {
                var changedFunctions = new HashSet<ulong>();
                for (int i = changes.Count - 1; i >= 0; --i) {
                    var change = changes[i];
                    Fact? current = Capture(change.After.Key);
                    bool matches = change.After.Excluded ? current == null : Equal(current, change.After);
                    if (!matches && current != null && change.After.Key.Kind == Kind.Abi)
                        changedFunctions.Add(change.After.Key.Address);
                    if (matches && !(change.Before == null && change.After.Key.Kind == Kind.Function
                        && changedFunctions.Contains(change.After.Key.Address)))
                        Restore(change.Before, change.After, retract: false);
                }
                CleanRetiredTags();
            }
        } finally {
            disposed = true;
            if (Current == this)
                Current = null;
            foreach (nint type in types)
                Core.BNFreeType(type);
            foreach (nint tag in registeredTags)
                Core.BNFreeTag(tag);
            Core.BNFreePlatform(platform);
            File.Delete(temporary);
        }
    }
}
