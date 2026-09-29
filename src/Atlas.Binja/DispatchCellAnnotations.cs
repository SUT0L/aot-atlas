using System.Globalization;
using System.Text;

namespace Atlas.Binja;

internal static unsafe class DispatchCellAnnotations {
    internal static void Apply(Symbols symbols, DataVariables variables, nint view, Extraction extraction,
        DispatchCells cells, ref ApplyStats stats, nint task) {
        if (cells.Cells.Count == 0)
            return;
        int nameLength = 64;
        foreach (var cell in cells.Cells)
            nameLength = Math.Max(nameLength, extraction.Names.Values[cell.InterfaceType].Length + 64);
        char[] text = new char[nameLength];
        byte[] buffer = new byte[Encoding.UTF8.GetMaxByteCount(nameLength) + 1];
        ulong original = extraction.Image.ImageBase;
        byte empty = 0;
        BoolConfidence unsigned = new() { Confidence = 255 };
        nint u64 = Core.BNCreateIntegerType(8, &unsigned, &empty);
        nint u16 = Core.BNCreateIntegerType(2, &unsigned, &empty);
        nint emptyType = Core.BNCreateVoidType();
        var emptyConfidence = new TypeConfidence(emptyType);
        BoolConfidence qualifier = new() { Confidence = 255 };
        nint pointer = Core.BNCreatePointerTypeOfWidth(8, &emptyConfidence, &qualifier, &qualifier, 0);
        Core.BNFreeType(emptyType);
        nint builder = Core.BNCreateStructureBuilder();
        Core.BNSetStructureBuilderPacked(builder, 1);
        var integer = new TypeConfidence(u64);
        var stub = new TypeConfidence(pointer);
        fixed (byte* names = "stub\0cache_or_interface\0"u8) {
            Core.BNAddStructureBuilderMemberAtOffset(builder, &stub, names, 0, 0, 0, 0, 0, 0);
            Core.BNAddStructureBuilderMemberAtOffset(builder, &integer, names + 5, 8, 0, 0, 0, 0, 0);
        }
        nint structure = Core.BNFinalizeStructureBuilder(builder);
        nint cellType = Core.BNCreateStructureType(structure);
        Core.BNFreeStructure(structure);
        Core.BNFreeStructureBuilder(builder);
        var terminators = new HashSet<ulong>();
        try {
            fixed (byte* name = buffer) {
                int processed = 0;
                foreach (var cell in cells.Cells) {
                    if (task != 0 && (processed++ & 1023) == 0 && Core.BNIsBackgroundTaskCancelled(task) != 0)
                        throw new OperationCanceledException();
                    "dispatch_cell::".CopyTo(text.AsSpan());
                    string owner = extraction.Names.Values[cell.InterfaceType];
                    owner.CopyTo(text.AsSpan(15));
                    int length = 15 + owner.Length;
                    "::slot_".CopyTo(text.AsSpan(length));
                    length += 7;
                    cell.Slot.TryFormat(text.AsSpan(length), out int digits, provider: CultureInfo.InvariantCulture);
                    length += digits;
                    text[length++] = ':';
                    text[length++] = ':';
                    (cell.Address - original).TryFormat(text.AsSpan(length), out digits, "X8", CultureInfo.InvariantCulture);
                    length += digits;
                    int bytes = Encoding.UTF8.GetBytes(text.AsSpan(0, length), buffer);
                    buffer[bytes] = 0;
                    ulong address = stats.ImageBase + cell.Address - original;
                    ulong contract = stats.ImageBase + extraction.Types.Types[cell.InterfaceType].Address - original;
                    ulong terminator = stats.ImageBase + cell.Terminator - original + 8;
                    symbols.DefineData(variables, address, cellType, name, ref stats);
                    Core.BNAddUserDataReference(view, address, stats.ImageBase + cell.Stub - original);
                    Core.BNAddUserDataReference(view, address + 8, contract);
                    Core.BNAddUserDataReference(view, address + 8, terminator);
                    stats.DataReferences += 3;

                    if (terminators.Add(terminator)) {
                        "dispatch_slot::".CopyTo(text.AsSpan());
                        (cell.Terminator - original).TryFormat(text.AsSpan(15), out digits, "X8", CultureInfo.InvariantCulture);
                        bytes = Encoding.UTF8.GetBytes(text.AsSpan(0, 15 + digits), buffer);
                        buffer[bytes] = 0;
                        symbols.DefineData(variables, terminator, u16, name, ref stats);
                    }
                    for (int i = cell.Uses.Start; i < cell.Uses.End; ++i) {
                        var use = cells.Uses[i];
                        Core.BNAddUserDataReference(view, stats.ImageBase + use.Definition - original, address);
                        Core.BNAddUserDataReference(view, stats.ImageBase + use.Instruction - original, address);
                        Core.BNAddUserDataReference(view, stats.ImageBase + use.Instruction - original, contract);
                        stats.DataReferences += 3;
                    }
                    for (int i = cell.DictionarySlots.Start; i < cell.DictionarySlots.End; ++i) {
                        ulong slot = extraction.Dictionaries.Slots[cells.DictionarySlots[i]].Address;
                        Core.BNAddUserDataReference(view, address, stats.ImageBase + slot - original);
                        ++stats.DataReferences;
                    }
                }
            }
        } finally {
            Core.BNFreeType(cellType);
            Core.BNFreeType(u16);
            Core.BNFreeType(u64);
            Core.BNFreeType(pointer);
        }
    }
}
