using System.Runtime.InteropServices;
using System.Text.Unicode;

namespace Atlas.Binja;

internal static unsafe class StringAnnotations {
    private readonly record struct Extent(ulong Start, ulong End);

    internal static void Apply(Symbols symbols, TagOwnership ownership, nint view, PeImage image, NativeStrings strings,
        ReadOnlySpan<CodeEdge> references, ref ApplyStats stats, nint task) {
        if (strings.Items.Count == 0)
            return;

        nuint count = 0;
        DataVariable* variables = Core.BNGetDataVariables(view, &count);
        var occupied = new Extent[checked((int)count)];
        int occupiedCount = 0;
        try {
            for (int i = 0; i < occupied.Length; ++i) {
                if (variables[i].AutoDiscovered != 0)
                    continue;

                ulong width = Core.BNGetTypeWidth(variables[i].Type);
                if (width != 0)
                    occupied[occupiedCount++] = new Extent(variables[i].Address, checked(variables[i].Address + width));
            }
        } finally {
            Core.BNFreeDataVariables(variables, count);
        }
        occupied.AsSpan(0, occupiedCount).Sort(static (left, right) => left.Start.CompareTo(right.Start));

        int maximum = 0;
        foreach (ref readonly var item in CollectionsMarshal.AsSpan(strings.Items))
            maximum = Math.Max(maximum, item.Data.Count / (item.Wide ? 2 : 1));
        byte[] text = new byte[checked(6 * maximum + 96)];
        Span<byte> symbol = stackalloc byte[64];
        var arrays = new Dictionary<(bool Wide, int Length), nint>();
        ownership.Reserve(strings.Items.Count);
        byte empty = 0;
        BoolConfidence signed = new() { Value = 1, Confidence = 255 };
        nint character;
        fixed (byte* name = "char\0"u8)
            character = Core.BNCreateIntegerType(1, &signed, name);
        nint wideCharacter = Core.BNCreateWideCharType(2, &empty);
        nint tagType;
        fixed (byte* name = "AOT Atlas strings\0"u8)
        fixed (byte* icon = "🔤\0"u8) {
            tagType = Core.BNGetTagType(view, name);
            if (tagType == 0) {
                tagType = Core.BNCreateTagType(view);
                Core.BNTagTypeSetName(tagType, name);
                Core.BNTagTypeSetIcon(tagType, icon);
                Core.BNAddTagType(view, tagType);
            }
        }

        try {
            int cursor = 0, processed = 0;
            ulong definedEnd = 0;
            fixed (byte* name = symbol) {
                foreach (ref readonly var item in CollectionsMarshal.AsSpan(strings.Items)) {
                    if (task != 0 && (processed++ & 1023) == 0 && Core.BNIsBackgroundTaskCancelled(task) != 0)
                        throw new OperationCanceledException();
                    int width = item.Wide ? 2 : 1;
                    ulong address = stats.ImageBase + item.Rva, end = address + (uint)item.Data.Count + (uint)width;
                    while (cursor < occupiedCount && occupied[cursor].End <= address)
                        ++cursor;
                    bool overlap = address < definedEnd || (cursor < occupiedCount && occupied[cursor].Start < end);
                    bool exact = cursor < occupiedCount && occupied[cursor].Start == address;
                    // Preserve user layouts
                    // Auto definitions can disappear during analysis, so they cant establish persistent string coverage
                    if (!overlap) {
                        var key = (item.Wide, item.Data.Count / width + 1);
                        if (!arrays.TryGetValue(key, out nint type)) {
                            var element = new TypeConfidence(item.Wide ? wideCharacter : character);
                            type = Core.BNCreateArrayType(&element, (uint)key.Item2);
                            arrays.Add(key, type);
                        }
                        var confidence = new TypeConfidence(type);
                        Core.BNDefineUserDataVariable(view, address, &confidence);
                        definedEnd = end;
                    }
                    if (!overlap || exact)
                        ++stats.DataVariables;

                    string encoding = item.Wide ? "utf16le" : "ascii";
                    Utf8.TryWrite(symbol, $"candidate::cstring::{encoding}::{item.Rva:X8}\0", out _);
                    symbols.Define(address, 3, name);
                    ++stats.Symbols;
                    Utf8.TryWrite(text, $"bytes::{encoding}::nul_terminated::", out int length);
                    length += FrozenText.Quote(image.FileData.AsSpan(item.Data.Start, item.Data.Count), text.AsSpan(length), item.Wide);
                    text[length] = 0;
                    DataTags.Set(ownership, view, tagType, address, text.AsSpan(0, length + 1));
                }
            }
            foreach (ref readonly var reference in references) {
                Core.BNAddUserDataReference(view, stats.ImageBase + (reference.Instruction - image.ImageBase),
                    stats.ImageBase + (reference.Target - image.ImageBase));
                ++stats.DataReferences;
            }
        } finally {
            foreach (nint type in arrays.Values)
                Core.BNFreeType(type);
            Core.BNFreeTagType(tagType);
            Core.BNFreeType(wideCharacter);
            Core.BNFreeType(character);
        }
    }
}
