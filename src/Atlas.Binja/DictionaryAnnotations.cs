using System.Runtime.InteropServices;
using System.Text;
using System.Text.Unicode;

namespace Atlas.Binja;

internal static unsafe class DictionaryAnnotations {
    internal static void Apply(
        Symbols symbols,
        TagOwnership ownership,
        DataVariables variables,
        nint view,
        Extraction extraction,
        nint pointer,
        nint headerPointer,
        ref ApplyStats stats,
        nint task) {
        var dictionaries = extraction.Dictionaries;
        if (dictionaries.Slots.Count == 0)
            return;

        ownership.Reserve(dictionaries.Slots.Count);

        var renderer = new MethodText(extraction);

        byte[] text = new byte[1024];
        Span<byte> symbol = stackalloc byte[128];

        ulong originalBase = extraction.Image.ImageBase;
        ulong nativeLayout = extraction.Header.Find(RtrSectionId.NativeLayoutInfo).Start;

        nint tagType = 0;

        try {
            fixed (byte* name = "AOT Atlas dictionaries\0"u8)
            fixed (byte* icon = "🧩\0"u8) {
                tagType = Core.BNGetTagType(view, name);

                if (tagType == 0) {
                    tagType = Core.BNCreateTagType(view);
                    Core.BNTagTypeSetName(tagType, name);
                    Core.BNTagTypeSetIcon(tagType, icon);
                    Core.BNAddTagType(view, tagType);
                }
            }

            // A reference to a later dictionary can create a user-layer void
            // placeholder, so define every verified slot before adding references.
            foreach (ref readonly var instance in CollectionsMarshal.AsSpan(dictionaries.Instances)) {
                for (int i = instance.Slots.Start; i < instance.Slots.End; ++i) {
                    if (task != 0 && (i & 1023) == 0 && Core.BNIsBackgroundTaskCancelled(task) != 0)
                        throw new OperationCanceledException();

                    ref readonly var slot = ref CollectionsMarshal.AsSpan(dictionaries.Slots)[i];
                    if (slot.Status != DictionarySlotStatus.Verified)
                        continue;

                    ref readonly var recipe = ref CollectionsMarshal.AsSpan(dictionaries.Recipes)[slot.Recipe];
                    ReadOnlySpan<char> kind = Kind(recipe);

                    Utf8.TryWrite(
                        symbol,
                        $"dictionary_slot::{instance.Address - originalBase:X8}::{slot.Address - instance.Address:X4}::{kind}\0",
                        out _);

                    ulong address = stats.ImageBase + (slot.Address - originalBase);
                    fixed (byte* name = symbol)
                        symbols.DefineData(variables, address,
                            recipe.Kind == DictionaryFixup.TypeHandle ? headerPointer : pointer, name);
                }
            }

            foreach (ref readonly var instance in CollectionsMarshal.AsSpan(dictionaries.Instances)) {
                var method = new MethodRecord(extraction, extraction.Maps.Methods.Count + instance.Method);
                ulong witness = stats.ImageBase
                    + (extraction.Header.Find(method.Section).Start + (uint)method.Vertex - originalBase);

                for (int i = instance.Slots.Start; i < instance.Slots.End; ++i) {
                    if (task != 0 && (i & 1023) == 0 && Core.BNIsBackgroundTaskCancelled(task) != 0)
                        throw new OperationCanceledException();

                    ref readonly var slot = ref CollectionsMarshal.AsSpan(dictionaries.Slots)[i];
                    if (slot.Status != DictionarySlotStatus.Verified)
                        continue;

                    ref readonly var recipe = ref CollectionsMarshal.AsSpan(dictionaries.Recipes)[slot.Recipe];
                    ulong address = stats.ImageBase + (slot.Address - originalBase);
                    ulong target = stats.ImageBase + (slot.Value - originalBase);

                    ReadOnlySpan<char> identity;
                    ReadOnlySpan<char> kind = Kind(recipe);

                    if (recipe.Kind == DictionaryFixup.MethodDictionary) {
                        var nested = new MethodRecord(extraction, extraction.Maps.Methods.Count + slot.Method - 1);
                        identity = renderer.Render(nested, false);

                        Core.BNAddUserDataReference(view, address,
                            stats.ImageBase
                                + (extraction.Header.Find(nested.Section).Start + (uint)nested.Vertex - originalBase));
                    } else if (recipe.Kind == DictionaryFixup.GvmDispatchCell) {
                        var contract = extraction.DispatchCellMetadata.Entries[slot.GvmCellMetadata - 1];
                        identity = string.Concat(extraction.Names.Values[slot.Type - 1], "::", contract.Method.Name);
                        Core.BNAddUserDataReference(view, address,
                            stats.ImageBase + extraction.Header.Find(contract.Section).Start + (uint)contract.Vertex - originalBase);
                    } else {
                        identity = extraction.Names.Values[slot.Type - 1];
                    }

                    if (identity.Contains('\0'))
                        throw new InvalidDataException("A dictionary target name contains a NUL and cant be represented by native annotations.");

                    int capacity = checked(Encoding.UTF8.GetMaxByteCount(identity.Length) + 80);
                    if (capacity > text.Length)
                        Array.Resize(ref text, Math.Max(capacity, text.Length * 2));

                    Utf8.TryWrite(text, $"native_layout::{recipe.Offset:X8}::{kind}::", out int prefix);
                    int length = prefix + Encoding.UTF8.GetBytes(identity, text.AsSpan(prefix));

                    if (recipe.Kind == DictionaryFixup.InterfaceCall) {
                        Utf8.TryWrite(text.AsSpan(length), $"::slot_{recipe.Number}", out int suffix);
                        length += suffix;
                    }

                    text[length] = 0;

                    DataTags.Set(ownership, view, tagType, address, text.AsSpan(0, length + 1));

                    Core.BNAddUserDataReference(view, address, target);
                    Core.BNAddUserDataReference(
                        view, address, stats.ImageBase + (nativeLayout + (uint)recipe.Offset - originalBase));
                    Core.BNAddUserDataReference(view, address, witness);

                    if (recipe.Kind is DictionaryFixup.InterfaceCall or DictionaryFixup.StaticData) {
                        Core.BNAddUserDataReference(view, address,
                            stats.ImageBase + (extraction.Types.Types[slot.Type - 1].Address - originalBase));
                    }
                }
            }
        } finally {
            if (tagType != 0)
                Core.BNFreeTagType(tagType);
        }
    }

    private static ReadOnlySpan<char> Kind(in DictionaryRecipe recipe) =>
        recipe.Kind == DictionaryFixup.MethodDictionary ? "MethodDictionary"
        : recipe.Kind == DictionaryFixup.GvmDispatchCell ? "GvmDispatchCell"
        : recipe.Kind == DictionaryFixup.TypeHandle ? "TypeHandle"
        : recipe.Kind == DictionaryFixup.InterfaceCall ? "InterfaceCall"
        : recipe.Number == 1 ? "GcStaticCell" : "NonGcStaticBase";
}
