using System.Buffers.Binary;
using System.Runtime.InteropServices;

namespace Atlas;

public enum DictionaryFixup : uint {
    Unknown, TypeHandle, InterfaceCall, MethodDictionary = 4, StaticData, UnwrapNullableType,
    FieldLdToken, MethodLdToken, AllocateObject, DefaultConstructor, ThreadStaticIndex,
    Method = 13, InstanceConstrainedMethod = 0x20, StaticConstrainedMethod, GenericConstrainedMethod,
    Unsupported = 0xee
}

public enum DictionarySlotStatus : byte { Unknown, Verified, Null, Unresolved, Conflict, Unsupported }

public struct DictionaryRecipe {
    public int Offset, Length, Type, SecondType;
    public DictionaryFixup Kind;
    public uint Number;
    public NativeMethodEntry Method;
}

public struct DictionaryLayout {
    public int Offset, Length, SlotCount, InterfaceSlots;
    public uint UnsupportedKind;
    public IndexRange Recipes;
}

public struct DictionaryInstance {
    public ulong Address;
    public int Method, Template, Layout;
    public IndexRange Slots;
}

public struct DictionarySlot {
    public ulong Address, Value;
    public int Recipe, Type, Method, Cell;
    public DictionarySlotStatus Status;
}

public sealed class GenericDictionaries {
    public readonly List<DictionaryLayout> Layouts = new();
    public readonly List<DictionaryRecipe> Recipes = new();
    public readonly List<DictionaryInstance> Instances = new();
    public readonly List<DictionarySlot> Slots = new();
    public readonly List<InterfaceDispatchCell> InterfaceCells = new();
    public int[] MethodLayouts = [], TypeLayouts = [];

    public void Read(PeImage image, ReadyToRun header, Metadata metadata, NativeLayout native,
        TemplateMaps templates, MapFormat format) {
        var section = header.Find(330);
        var data = section.Length == 0 ? default : image.FileSpan(section.Start, checked((int)section.Length));
        MethodLayouts = new int[templates.Methods.Count];
        TypeLayouts = new int[templates.Types.Count];
        var offsets = new Dictionary<int, int>();

        for (int group = 0; group < 2; ++group) {
            var indices = group == 0 ? MethodLayouts : TypeLayouts;
            for (int index = 0; index < indices.Length; ++index) {
                uint offset = group == 0 ? templates.Methods[index].LayoutOffset : templates.Types[index].LayoutOffset;
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
                    indices[index] = existing;
                    continue;
                }

                var reader = new NativeReader(data, start);
                int count = checked((int)reader.Unsigned());
                if (count > reader.Remaining)
                    throw new InvalidDataException("Dictionary slot count exceeds NativeLayout storage.");
                var layout = new DictionaryLayout { Offset = start, SlotCount = count };
                int first = Recipes.Count;
                Recipes.EnsureCapacity(checked(first + count));
                for (int slot = 0; slot < count; ++slot) {
                    var recipe = new DictionaryRecipe { Offset = reader.Position, Kind = (DictionaryFixup)reader.Unsigned() };
                    if (recipe.Kind == DictionaryFixup.Unknown)
                        throw new InvalidDataException("Dictionary layout contains the reserved null fixup kind.");
                    if (recipe.Kind == DictionaryFixup.InstanceConstrainedMethod && header.Major < 10) {
                        layout.UnsupportedKind = (uint)recipe.Kind;
                        break;
                    }
                    switch (recipe.Kind) {
                        case DictionaryFixup.TypeHandle:
                        case DictionaryFixup.UnwrapNullableType:
                        case DictionaryFixup.AllocateObject:
                        case DictionaryFixup.DefaultConstructor:
                        case DictionaryFixup.ThreadStaticIndex:
                            recipe.Type = native.TypeSignature(ref reader);
                            break;
                        case DictionaryFixup.InterfaceCall:
                        case DictionaryFixup.StaticData:
                        case DictionaryFixup.FieldLdToken:
                            recipe.Type = native.TypeSignature(ref reader);
                            recipe.Number = reader.Unsigned();
                            if (recipe.Kind == DictionaryFixup.StaticData && recipe.Number is not (1 or 2))
                                throw new InvalidDataException("Dictionary static-data kind is neither GC nor non-GC.");
                            break;
                        case DictionaryFixup.MethodDictionary:
                        case DictionaryFixup.MethodLdToken:
                        case DictionaryFixup.Method:
                            recipe.Method = native.MethodEntry((uint)reader.Position, metadata, format);
                            reader.Position = recipe.Method.End;
                            if (recipe.Kind == DictionaryFixup.MethodDictionary && recipe.Method.Arguments.Count == 0)
                                throw new InvalidDataException("Method-dictionary recipe has no generic method arguments.");
                            break;
                        case DictionaryFixup.InstanceConstrainedMethod:
                        case DictionaryFixup.StaticConstrainedMethod:
                            recipe.Type = native.TypeSignature(ref reader);
                            recipe.SecondType = native.TypeSignature(ref reader);
                            recipe.Number = reader.Unsigned();
                            break;
                        case DictionaryFixup.GenericConstrainedMethod:
                            recipe.Type = native.TypeSignature(ref reader);
                            recipe.Method = native.MethodEntry((uint)reader.Position, metadata, format);
                            reader.Position = recipe.Method.End;
                            break;
                        case DictionaryFixup.Unsupported:
                            if (reader.Unsigned() != 0xDEADBEEF)
                                throw new InvalidDataException("Unsupported dictionary recipe has an invalid sentinel.");
                            break;
                        default:
                            // An unknown variable-length payload prevents locating later recipes
                            // Preserve the proven prefix and expose the unsupported kind explicitly
                            layout.UnsupportedKind = (uint)recipe.Kind;
                            slot = count;
                            continue;
                    }
                    recipe.Length = reader.Position - recipe.Offset;
                    if (recipe.Kind == DictionaryFixup.InterfaceCall)
                        ++layout.InterfaceSlots;
                    Recipes.Add(recipe);
                }
                layout.Length = reader.Position - start;
                layout.Recipes = new IndexRange(first, Recipes.Count - first);
                Layouts.Add(layout);
                indices[index] = Layouts.Count;
                offsets.Add(start, Layouts.Count);
            }
        }
    }

    public void Bind(Extraction extraction) {
        var methods = CollectionsMarshal.AsSpan(extraction.Generics.Methods);
        var methodArguments = CollectionsMarshal.AsSpan(extraction.Generics.Arguments);
        var types = CollectionsMarshal.AsSpan(extraction.Types.Types);
        var signatures = extraction.Metadata.Signatures;
        var bindings = extraction.Fields.Bindings;
        var methodHeads = new Dictionary<ulong, int>(methods.Length);
        var next = new int[methods.Length];
        int capacity = 0, interfaceCapacity = 0;
        for (int i = 0; i < methods.Length; ++i) {
            if (methods[i].Dictionary == 0)
                continue;
            ref int head = ref CollectionsMarshal.GetValueRefOrAddDefault(methodHeads, methods[i].Dictionary, out _);
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

        for (int i = 0; i < methods.Length; ++i) {
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
                    Recipe = recipeIndex, Address = address,
                    Value = BinaryPrimitives.ReadUInt64LittleEndian(extraction.Memory.Read(address, 8)),
                    Status = DictionarySlotStatus.Unsupported
                };
                if (recipe.Kind is DictionaryFixup.TypeHandle or DictionaryFixup.StaticData or DictionaryFixup.InterfaceCall)
                    slot.Type = bindings.Resolve(recipe.Type, owner, arguments);

                if (recipe.Kind == DictionaryFixup.TypeHandle) {
                    slot.Status = slot.Type == 0 ? DictionarySlotStatus.Unresolved
                        : slot.Value == types[slot.Type - 1].Address ? DictionarySlotStatus.Verified : DictionarySlotStatus.Conflict;
                } else if (recipe.Kind == DictionaryFixup.InterfaceCall) {
                    slot.Status = DictionarySlotStatus.Unresolved;
                    if (slot.Type != 0 && slot.Value != 0) {
                        var status = DispatchCells.Read(extraction, dispatchStubs, slot.Value, out var cell,
                            types[slot.Type - 1].Address, recipe.Number);
                        if (status == DispatchCellStatus.Valid) {
                            slot.Status = cell.InterfaceType == slot.Type - 1 && cell.Slot == recipe.Number
                                ? DictionarySlotStatus.Verified : DictionarySlotStatus.Conflict;
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
                } else if (recipe.Kind == DictionaryFixup.StaticData) {
                    slot.Status = DictionarySlotStatus.Unresolved;
                    if (slot.Type != 0 && staticIndex.TryGetValue(types[slot.Type - 1].Address, out int index) && index > 0) {
                        ref readonly var storage = ref statics[index - 1];
                        ulong expected = recipe.Number == 1 ? storage.GcCell : storage.NonGcBase;
                        if (expected != 0)
                            slot.Status = expected == slot.Value ? DictionarySlotStatus.Verified : DictionarySlotStatus.Conflict;
                    }
                } else if (recipe.Kind == DictionaryFixup.MethodDictionary) {
                    slot.Status = DictionarySlotStatus.Unresolved;
                    int declaring = bindings.Resolve(recipe.Method.DeclaringType, owner, arguments);
                    if (declaring != 0 && methodHeads.TryGetValue(slot.Value, out int candidate)) {
                        for (; candidate != 0; candidate = next[candidate - 1]) {
                            ref readonly var target = ref methods[candidate - 1];
                            bool identity = recipe.Method.Identity.MetadataOffset != 0 && target.MetadataOffset != 0
                                ? recipe.Method.Identity.MetadataOffset == target.MetadataOffset
                                : SharedMethods.EqualMethod(signatures, bindings, recipe.Method.Identity.Signature, target.Signature);
                            if (target.DeclaringType != types[declaring - 1].Address || target.Name != recipe.Method.Identity.Name || !identity
                                || target.Arguments.Count != recipe.Method.Arguments.Count
                                || target.AsyncVariant != ((recipe.Method.Flags & 8) != 0 && extraction.Header.Major >= 18))
                                continue;
                            bool match = true;
                            for (int argument = 0; argument < target.Arguments.Count; ++argument) {
                                int binding = bindings.Resolve(signatures.Edges[recipe.Method.Arguments.Start + argument], owner, arguments);
                                if (binding == 0 || types[binding - 1].Address != methodArguments[target.Arguments.Start + argument]) {
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
                Address = method.Dictionary, Method = i, Template = template - 1, Layout = layoutIndex,
                Slots = new IndexRange(first, Slots.Count - first)
            });
        }
    }
}
