using System.Buffers.Binary;
using System.Runtime.InteropServices;

namespace Atlas;

public enum DictionaryFixup : uint {
    Unknown,
    TypeHandle,
    InterfaceCall,
    GvmDispatchCell,
    MethodDictionary = 4,
    StaticData,
    UnwrapNullableType,
    FieldLdToken,
    MethodLdToken,
    AllocateObject,
    DefaultConstructor,
    ThreadStaticIndex,
    Method = 13,
    IsInstance = 0x0e,
    CastClass,
    AllocateArray,
    TypeSize = 0x12,
    FieldOffset,
    CallingConventionConverter,
    VTableOffset,
    LegacyConstrainedMethod,
    LegacyGenericConstrainedMethod,
    LegacyDirectConstrainedMethod,
    PointerToOtherSlot,
    InstanceConstrainedMethod = 0x20,
    StaticConstrainedMethod,
    GenericConstrainedMethod,
    Unsupported = 0xee,
    // RTR 9.1 encodes integers as 0x20; later formats reuse that tag for methods.
    IntegerValue = 0x10020
}

public enum DictionarySlotStatus : byte {
    Unknown,
    Verified,
    Null,
    Unresolved,
    Conflict,
    Unsupported
}

public struct DictionaryRecipe {
    public int Offset;
    public int Length;
    public int PayloadOffset;

    internal int Type;
    internal int SecondType;
    internal int ConverterSignature;
    public DictionaryFixup Kind;
    public uint Number;
    public string? FieldName;
    public NativeMethodEntry Method;

    public readonly uint EncodedKind => Kind == DictionaryFixup.IntegerValue ? 0x20 : (uint)Kind;
}

public struct DictionaryLayout {
    public int Offset;
    public int Length;

    public int SlotCount;
    public int InterfaceSlots;
    public uint UnsupportedKind;
    public IndexRange Recipes;
}

public readonly record struct DictionarySignatureGap(
    int LayoutOffset,
    int RecipeOffset,
    uint Kind,
    int RemainingSlots);

public struct DictionaryInstance {
    public ulong Address;
    public int Method;
    public int Template;
    public int Layout;
    public IndexRange Slots;
}

public struct DictionarySlot {
    public ulong Address;
    public ulong Value;

    public int Recipe;
    internal int Type;
    public int Method;
    public int Cell;
    // One-based source contract; Status independently records semantic verification.
    public int GvmCellMetadata;
    public DictionarySlotStatus Status;
}

public sealed class GenericDictionaries {
    internal readonly List<DictionaryLayout> Layouts = new();
    internal readonly List<DictionaryRecipe> Recipes = new();
    internal readonly List<DictionaryInstance> Instances = new();
    internal readonly List<DictionarySlot> Slots = new();
    internal readonly List<InterfaceDispatchCell> InterfaceCells = new();

    internal int[] MethodLayouts = [];
    internal int[] TypeLayouts = [];

    public ReadOnlySpan<DictionaryLayout> LayoutEntries => CollectionsMarshal.AsSpan(Layouts);
    public ReadOnlySpan<DictionaryRecipe> RecipeEntries => CollectionsMarshal.AsSpan(Recipes);
    public ReadOnlySpan<DictionaryInstance> InstanceEntries => CollectionsMarshal.AsSpan(Instances);
    public ReadOnlySpan<DictionarySlot> SlotEntries => CollectionsMarshal.AsSpan(Slots);
    public ReadOnlySpan<InterfaceDispatchCell> InterfaceCellEntries => CollectionsMarshal.AsSpan(InterfaceCells);

    private List<DictionarySignatureGap>? signatureGaps;
    public ReadOnlySpan<DictionarySignatureGap> SignatureGaps => signatureGaps is null
        ? default
        : CollectionsMarshal.AsSpan(signatureGaps);

    internal void Read(
        PeImage image,
        ReadyToRun header,
        MetadataBuilder metadata,
        NativeLayout native,
        TemplateMaps templates,
        MapFormat format,
        CancellationToken cancellationToken = default) =>
        Decode(image, header, metadata, native, templates, format, retainRecipes: true, cancellationToken);

    // Dictionary signatures can contribute runtime type roots even when no dictionary
    // interpretation is requested. Visit them in the same order without retaining or
    // validating the independent dictionary operations.
    internal void ReadSignatures(
        PeImage image,
        ReadyToRun header,
        MetadataBuilder metadata,
        NativeLayout native,
        TemplateMaps templates,
        MapFormat format,
        CancellationToken cancellationToken = default) =>
        Decode(image, header, metadata, native, templates, format, retainRecipes: false, cancellationToken);

    private void Decode(
        PeImage image,
        ReadyToRun header,
        MetadataBuilder metadata,
        NativeLayout native,
        TemplateMaps templates,
        MapFormat format,
        bool retainRecipes,
        CancellationToken cancellationToken) {
        cancellationToken.ThrowIfCancellationRequested();

        var section = header.Find(RtrSectionId.NativeLayoutInfo);
        var data = section.Length == 0
            ? default
            : image.FileSpan(section.Start, checked((int)section.Length));

        if (retainRecipes) {
            MethodLayouts = new int[templates.Methods.Count];
            TypeLayouts = new int[templates.Types.Count];
        }

        var offsets = new Dictionary<int, int>();

        // Decode and share dictionary layouts by their NativeLayout offset.
        for (int group = 0; group < 2; ++group) {
            var indices = group == 0 ? MethodLayouts : TypeLayouts;
            int templateCount = group == 0 ? templates.Methods.Count : templates.Types.Count;

            for (int index = 0; index < templateCount; ++index) {
                cancellationToken.ThrowIfCancellationRequested();

                uint offset = group == 0
                    ? templates.Methods[index].LayoutOffset
                    : templates.Types[index].LayoutOffset;
                var bag = new NativeReader(data, checked((int)offset));

                int start = -1;

                while (true) {
                    uint kind = bag.Unsigned();
                    if (kind == 0)
                        break;

                    int origin = bag.Position;
                    if (kind == 0x40) {
                        if (start >= 0)
                            throw new InvalidDataException("Template bag repeats its dictionary layout.");

                        start = checked(origin + bag.Signed());
                        if (start < 0 || start >= data.Length)
                            throw new InvalidDataException("Dictionary layout is outside NativeLayout storage.");
                    } else {
                        bag.Unsigned();
                    }
                }

                if (start < 0)
                    continue;

                if (offsets.TryGetValue(start, out int existing)) {
                    if (retainRecipes)
                        indices[index] = existing;

                    continue;
                }

                var reader = new NativeReader(data, start);
                int count = checked((int)reader.Unsigned());
                if (count > reader.Remaining)
                    throw new InvalidDataException("Dictionary slot count exceeds NativeLayout storage.");

                var layout = new DictionaryLayout {
                    Offset = start,
                    SlotCount = count
                };

                int first = Recipes.Count;
                if (retainRecipes)
                    Recipes.EnsureCapacity(checked(first + count));

                for (int slot = 0; slot < count; ++slot) {
                    cancellationToken.ThrowIfCancellationRequested();

                    int recipeOffset = reader.Position;
                    uint encodedKind = reader.Unsigned();
                    var recipe = new DictionaryRecipe {
                        Offset = recipeOffset,
                        Kind = (DictionaryFixup)encodedKind
                    };
                    recipe.PayloadOffset = reader.Position;
                    if (recipe.Kind == DictionaryFixup.Unknown)
                        throw new InvalidDataException("Dictionary layout contains the reserved null fixup kind.");

                    if (recipe.Kind == DictionaryFixup.InstanceConstrainedMethod && header.Format.LegacyDictionaryRecipes)
                        recipe.Kind = DictionaryFixup.IntegerValue;

                    bool legacyKind = recipe.Kind is >= DictionaryFixup.IsInstance and <= DictionaryFixup.PointerToOtherSlot;
                    if (encodedKind == (uint)DictionaryFixup.IntegerValue
                        || (legacyKind && !header.Format.LegacyDictionaryRecipes)
                        || (recipe.Kind == DictionaryFixup.InstanceConstrainedMethod && !header.Format.InstanceConstrainedMethods)
                        || (recipe.Kind == DictionaryFixup.GvmDispatchCell && !header.Format.SeparateDispatchCellInfo)) {
                        layout.UnsupportedKind = encodedKind;
                        (signatureGaps ??= new()).Add(new(start, recipe.Offset, encodedKind, count - slot));
                        break;
                    }

                    switch (recipe.Kind) {
                        case DictionaryFixup.TypeHandle:
                        case DictionaryFixup.UnwrapNullableType:
                        case DictionaryFixup.AllocateObject:
                        case DictionaryFixup.DefaultConstructor:
                        case DictionaryFixup.ThreadStaticIndex:
                        case DictionaryFixup.IsInstance:
                        case DictionaryFixup.CastClass:
                        case DictionaryFixup.AllocateArray:
                        case DictionaryFixup.TypeSize:
                            recipe.Type = native.TypeSignature(ref reader);
                            break;

                        case DictionaryFixup.InterfaceCall:
                        case DictionaryFixup.StaticData:
                        case DictionaryFixup.FieldOffset:
                        case DictionaryFixup.VTableOffset:
                            recipe.Type = native.TypeSignature(ref reader);
                            recipe.Number = reader.Unsigned();
                            if (retainRecipes && recipe.Kind == DictionaryFixup.StaticData && recipe.Number is not (1 or 2))
                                throw new InvalidDataException("Dictionary static-data kind is neither GC nor non-GC.");
                            break;

                        case DictionaryFixup.GvmDispatchCell:
                        case DictionaryFixup.MethodDictionary:
                        case DictionaryFixup.Method:
                            recipe.Method = native.MethodEntry((uint)reader.Position, metadata, format);
                            reader.Position = recipe.Method.End;
                            if (retainRecipes
                                && (recipe.Kind is DictionaryFixup.GvmDispatchCell or DictionaryFixup.MethodDictionary)
                                && recipe.Method.Arguments.Count == 0)
                                throw new InvalidDataException("Generic-method dictionary recipe has no method arguments.");
                            break;

                        case DictionaryFixup.FieldLdToken:
                            ReflectionMaps.RequireGrammar(format);
                            if (format == MapFormat.Legacy) {
                                var payload = RelativePayload(data, ref reader);
                                recipe.PayloadOffset = payload.Position;
                                recipe.Type = native.TypeSignature(ref payload);
                                recipe.FieldName = payload.String();
                            } else {
                                recipe.Type = native.TypeSignature(ref reader);
                                recipe.Number = reader.Unsigned();
                            }

                            break;

                        case DictionaryFixup.MethodLdToken:
                            recipe.Method = TokenMethod(data, ref reader, native, metadata, format, out recipe.PayloadOffset);
                            break;

                        case DictionaryFixup.InstanceConstrainedMethod:
                        case DictionaryFixup.StaticConstrainedMethod:
                        case DictionaryFixup.LegacyConstrainedMethod:
                        case DictionaryFixup.LegacyDirectConstrainedMethod:
                            recipe.Type = native.TypeSignature(ref reader);
                            recipe.SecondType = native.TypeSignature(ref reader);
                            recipe.Number = reader.Unsigned();
                            break;

                        case DictionaryFixup.GenericConstrainedMethod:
                        case DictionaryFixup.LegacyGenericConstrainedMethod:
                            recipe.Type = native.TypeSignature(ref reader);
                            recipe.Method = TokenMethod(data, ref reader, native, metadata, format, out recipe.PayloadOffset);
                            break;

                        case DictionaryFixup.CallingConventionConverter:
                            recipe.Number = reader.Unsigned();
                            var converter = RelativePayload(data, ref reader);
                            recipe.PayloadOffset = converter.Position;
                            recipe.ConverterSignature = native.MethodSignature((uint)converter.Position);
                            if (retainRecipes && recipe.Number > 2)
                                throw new InvalidDataException("Dictionary calling-convention converter kind is outside 0..2.");
                            break;

                        case DictionaryFixup.IntegerValue:
                        case DictionaryFixup.PointerToOtherSlot:
                            recipe.Number = reader.Unsigned();
                            if (retainRecipes && recipe.Kind == DictionaryFixup.PointerToOtherSlot && recipe.Number >= count)
                                throw new InvalidDataException("Dictionary slot pointer is outside its layout.");
                            break;

                        case DictionaryFixup.Unsupported:
                            uint sentinel = reader.Unsigned();
                            if (retainRecipes && sentinel != 0xDEADBEEF)
                                throw new InvalidDataException("Unsupported dictionary recipe has an invalid sentinel.");
                            break;

                        default:
                            // An unknown variable-length payload prevents locating later recipes
                            // Preserve the proven prefix and expose the unsupported kind explicitly
                            layout.UnsupportedKind = encodedKind;
                            (signatureGaps ??= new()).Add(new(start, recipe.Offset, encodedKind, count - slot));
                            slot = count;
                            continue;
                    }

                    recipe.Length = reader.Position - recipe.Offset;
                    if (recipe.Kind == DictionaryFixup.InterfaceCall)
                        ++layout.InterfaceSlots;

                    if (retainRecipes)
                        Recipes.Add(recipe);
                }

                layout.Length = reader.Position - start;
                layout.Recipes = new IndexRange(first, Recipes.Count - first);

                if (retainRecipes) {
                    Layouts.Add(layout);
                    indices[index] = Layouts.Count;
                }

                offsets.Add(start, offsets.Count + 1);
            }
        }
    }

    private static NativeReader RelativePayload(ReadOnlySpan<byte> data, scoped ref NativeReader reader) {
        int origin = reader.Position;
        long target = (long)origin + reader.Signed();
        if (target < 0 || target >= data.Length)
            throw new InvalidDataException("Dictionary payload is outside NativeLayout storage.");

        return new NativeReader(data, (int)target);
    }

    private static NativeMethodEntry TokenMethod(
        ReadOnlySpan<byte> data,
        scoped ref NativeReader reader,
        NativeLayout native,
        MetadataBuilder metadata,
        MapFormat format,
        out int offset) {
        var payload = format == MapFormat.Legacy ? RelativePayload(data, ref reader) : reader;
        offset = payload.Position;
        var method = native.MethodEntry((uint)offset, metadata, format);
        if (format != MapFormat.Legacy)
            reader.Position = method.End;

        return method;
    }

    internal void Bind(Extraction extraction, CancellationToken cancellationToken = default) {
        cancellationToken.ThrowIfCancellationRequested();

        var methods = CollectionsMarshal.AsSpan(extraction.Generics.Methods);
        var methodArguments = CollectionsMarshal.AsSpan(extraction.Generics.Arguments);

        var types = CollectionsMarshal.AsSpan(extraction.Types.Types);

        var signatures = extraction.Signatures;
        var bindings = extraction.Bindings;
        SignatureComparison? comparison = null;

        // Index method dictionaries and reserve their retained recipe counts.
        var methodHeads = new Dictionary<ulong, int>(methods.Length);
        var next = new int[methods.Length];

        int capacity = 0;
        int interfaceCapacity = 0;

        for (int i = 0; i < methods.Length; ++i) {
            cancellationToken.ThrowIfCancellationRequested();

            if (methods[i].Dictionary == 0)
                continue;

            ref int head = ref CollectionsMarshal.GetValueRefOrAddDefault(
                methodHeads,
                methods[i].Dictionary,
                out _);
            next[i] = head;
            head = i + 1;

            int template = extraction.Shared.Templates[i];
            if (template > 0 && MethodLayouts[template - 1] != 0) {
                var layout = Layouts[MethodLayouts[template - 1] - 1];
                capacity = checked(capacity + layout.Recipes.Count);
                interfaceCapacity = checked(interfaceCapacity + layout.InterfaceSlots);
            }
        }

        Slots.EnsureCapacity(capacity);
        InterfaceCells.EnsureCapacity(interfaceCapacity);
        Instances.EnsureCapacity(methodHeads.Count);

        var dispatchStubs = new Dictionary<ulong, byte>();

        var statics = CollectionsMarshal.AsSpan(extraction.Statics.Generics);
        var staticIndex = new Dictionary<ulong, int>(statics.Length);

        for (int i = 0; i < statics.Length; ++i) {
            ref int index = ref CollectionsMarshal.GetValueRefOrAddDefault(staticIndex, statics[i].Type, out _);
            index = index == 0 ? i + 1 : -1;
        }

        // Resolve each dictionary slot against its retained recipe.
        for (int i = 0; i < methods.Length; ++i) {
            cancellationToken.ThrowIfCancellationRequested();

            ref readonly var method = ref methods[i];
            int template = extraction.Shared.Templates[i];
            if (method.Dictionary == 0 || template <= 0)
                continue;

            int layoutIndex = MethodLayouts[template - 1];
            IndexRange recipes = layoutIndex == 0 ? default : Layouts[layoutIndex - 1].Recipes;

            var arguments = methodArguments.Slice(method.Arguments.Start, method.Arguments.Count);
            int owner = extraction.Types.Index[method.DeclaringType] + 1;

            int first = Slots.Count;

            for (int recipeIndex = recipes.Start; recipeIndex < recipes.End; ++recipeIndex) {
                ref readonly var recipe = ref CollectionsMarshal.AsSpan(Recipes)[recipeIndex];
                ulong address = checked(method.Dictionary + (uint)(recipeIndex - recipes.Start) * 8UL);
                var slot = new DictionarySlot {
                    Recipe = recipeIndex,
                    Address = address,
                    Value = BinaryPrimitives.ReadUInt64LittleEndian(extraction.Memory.Read(address, 8)),
                    Status = DictionarySlotStatus.Unsupported
                };

                if (recipe.Kind is DictionaryFixup.TypeHandle
                    or DictionaryFixup.StaticData
                    or DictionaryFixup.InterfaceCall)
                    slot.Type = bindings.Resolve(recipe.Type, owner, arguments);

                if (recipe.Kind == DictionaryFixup.TypeHandle) {
                    slot.Status = slot.Type == 0
                        ? DictionarySlotStatus.Unresolved
                        : slot.Value == types[slot.Type - 1].Address
                            ? DictionarySlotStatus.Verified
                            : DictionarySlotStatus.Conflict;
                } else if (recipe.Kind == DictionaryFixup.InterfaceCall) {
                    slot.Status = DictionarySlotStatus.Unresolved;
                    if (slot.Type != 0 && slot.Value != 0) {
                        var status = DispatchCells.Read(
                            extraction,
                            dispatchStubs,
                            slot.Value,
                            out var cell,
                            types[slot.Type - 1].Address,
                            recipe.Number);
                        if (status == DispatchCellStatus.Valid) {
                            slot.Status = cell.InterfaceType == slot.Type - 1 && cell.Slot == recipe.Number
                                ? DictionarySlotStatus.Verified
                                : DictionarySlotStatus.Conflict;

                            if (slot.Status == DictionarySlotStatus.Verified) {
                                InterfaceCells.Add(cell);
                                slot.Cell = InterfaceCells.Count;
                            }
                        } else if (status == DispatchCellStatus.ContractMismatch) {
                            slot.Status = DictionarySlotStatus.Conflict;
                        } else if (status == DispatchCellStatus.UnsupportedEncoding) {
                            slot.Status = DictionarySlotStatus.Unsupported;
                        }
                    }
                } else if (recipe.Kind == DictionaryFixup.GvmDispatchCell) {
                    slot.Status = DictionarySlotStatus.Unresolved;
                    slot.Type = bindings.Resolve(recipe.Method.DeclaringType, owner, arguments);
                    int metadataIndex = extraction.DispatchCellMetadata.Find(slot.Value);
                    if (metadataIndex >= 0) {
                        ref readonly var contract = ref extraction.DispatchCellMetadata.Entries[metadataIndex];
                        bool alignedGvm = contract.IsGvm && (slot.Value - contract.FirstCell) % 16 == 0;
                        if (alignedGvm)
                            slot.GvmCellMetadata = metadataIndex + 1;

                        if (slot.Type != 0 && contract.Status == MetadataFactStatus.Valid) {
                            bool identity = recipe.Method.Identity.MetadataOffset != 0 && contract.Method.MetadataOffset != 0
                                ? recipe.Method.Identity.MetadataOffset == contract.Method.MetadataOffset
                                : (comparison ??= new(signatures, bindings)).EqualMethod(
                                    recipe.Method.Identity.Signature, contract.Method.Signature);
                            bool match = alignedGvm
                                && contract.Type == types[slot.Type - 1].Address
                                && recipe.Method.Identity.Name == contract.Method.Name
                                && identity
                                && recipe.Method.Arguments.Count == contract.Arguments.Count
                                && ((recipe.Method.Flags & 8) != 0) == contract.Method.AsyncVariant
                                && ((recipe.Method.Flags & 0x10) != 0) == contract.Method.ReturnDroppingAsyncThunk;

                            for (int argument = 0; match && argument < contract.Arguments.Count; ++argument) {
                                int binding = bindings.Resolve(
                                    signatures.Edges[recipe.Method.Arguments.Start + argument], owner, arguments);
                                match = binding != 0 && types[binding - 1].Address
                                    == extraction.DispatchCellMetadata.ArgumentAddresses[contract.Arguments.Start + argument];
                            }

                            slot.Status = match ? DictionarySlotStatus.Verified : DictionarySlotStatus.Conflict;
                        }
                    }
                } else if (recipe.Kind == DictionaryFixup.StaticData) {
                    slot.Status = DictionarySlotStatus.Unresolved;
                    if (slot.Type != 0
                        && staticIndex.TryGetValue(types[slot.Type - 1].Address, out int index)
                        && index > 0) {
                        ref readonly var storage = ref statics[index - 1];
                        ulong expected = recipe.Number == 1 ? storage.GcCell : storage.NonGcBase;
                        if (expected != 0)
                            slot.Status = expected == slot.Value
                                ? DictionarySlotStatus.Verified
                                : DictionarySlotStatus.Conflict;
                    }
                } else if (recipe.Kind == DictionaryFixup.MethodDictionary) {
                    slot.Status = DictionarySlotStatus.Unresolved;

                    int declaring = bindings.Resolve(recipe.Method.DeclaringType, owner, arguments);
                    if (declaring != 0 && methodHeads.TryGetValue(slot.Value, out int candidate)) {
                        for (; candidate != 0; candidate = next[candidate - 1]) {
                            ref readonly var target = ref methods[candidate - 1];
                            bool identity = recipe.Method.Identity.MetadataOffset != 0 && target.MetadataOffset != 0
                                ? recipe.Method.Identity.MetadataOffset == target.MetadataOffset
                                : (comparison ??= new(signatures, bindings)).EqualMethod(
                                    recipe.Method.Identity.Signature,
                                    target.Signature);
                            if (target.DeclaringType != types[declaring - 1].Address
                                || target.Name != recipe.Method.Identity.Name
                                || !identity
                                || target.Arguments.Count != recipe.Method.Arguments.Count
                                || target.AsyncVariant != ((recipe.Method.Flags & 8) != 0
                                    && extraction.Header.Format.AsyncMethodVariants)
                                || target.ReturnDroppingAsyncThunk != ((recipe.Method.Flags & 0x10) != 0))
                                continue;

                            bool match = true;

                            for (int argument = 0; argument < target.Arguments.Count; ++argument) {
                                int binding = bindings.Resolve(
                                    signatures.Edges[recipe.Method.Arguments.Start + argument],
                                    owner,
                                    arguments);
                                if (binding == 0
                                    || types[binding - 1].Address != methodArguments[target.Arguments.Start + argument]) {
                                    match = false;
                                    break;
                                }
                            }

                            if (match) {
                                if (slot.Method != 0) {
                                    slot.Method = 0;
                                    slot.Status = DictionarySlotStatus.Unresolved;
                                    break;
                                }

                                slot.Method = candidate;
                                slot.Status = DictionarySlotStatus.Verified;
                            }
                        }
                    }
                }

                // A compiler-emitted zero can represent a failed target, not a lazy fixup
                if (slot.Value == 0)
                    slot.Status = DictionarySlotStatus.Null;

                Slots.Add(slot);
            }

            Instances.Add(new DictionaryInstance {
                Address = method.Dictionary,
                Method = i,
                Template = template - 1,
                Layout = layoutIndex,
                Slots = new IndexRange(first, Slots.Count - first)
            });
        }
    }
}
