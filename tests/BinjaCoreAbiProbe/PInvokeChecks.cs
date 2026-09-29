using System.Runtime.InteropServices;
using Atlas.Binja;

internal static unsafe class PInvokeChecks {
    internal static void Run() {
        byte empty = 0;
        BoolConfidence unsigned = new() { Confidence = 255 }, qualifier = default;
        nint u32 = Core.BNCreateIntegerType(4, &unsigned, &empty);
        nint u64 = Core.BNCreateIntegerType(8, &unsigned, &empty);
        var target = new TypeConfidence(u32);
        nint pointer = Core.BNCreatePointerTypeOfWidth(8, &target, &qualifier, &qualifier, 0);
        string[] moduleNames = ["module_handle", "module_name", "calling_assembly_type", "search_path"];
        string[] methodNames = ["target", "entry_point", "module", "flags"];
        for (int key = 0; key < 3; ++key) {
            nint original = PInvokeTypes.Cell(key == 0, pointer, key == 2 ? u64 : pointer, pointer, u32);
            nint type = Core.BNNewTypeReference(original);
            Core.BNFreeType(original);
            Assert(Core.BNGetTypeWidth(type) == 28);
            nint structure = Inspect.BNGetTypeStructure(type);
            Assert(Inspect.BNIsStructurePacked(structure) != 0);
            nuint count = 0;
            var members = Inspect.BNGetStructureMembers(structure, &count);
            Assert(count == 4);
            for (int i = 0; i < 4; ++i) {
                Assert(Marshal.PtrToStringUTF8(members[i].Name) == (key == 0 ? moduleNames[i] : methodNames[i]));
                Assert(members[i].Offset == (uint)i * 8 && Core.BNGetTypeWidth(members[i].Type) == (i == 3 ? 4U : 8U));
                Assert(Inspect.BNGetTypeClass(members[i].Type) == (i == 3 || (key == 2 && i == 1) ? 2 : 6));
            }
            Inspect.BNFreeStructureMemberList(members, count);
            Core.BNFreeStructure(structure);
            Core.BNFreeType(type);
        }
        Core.BNFreeType(pointer);
        Core.BNFreeType(u64);
        Core.BNFreeType(u32);
        Console.WriteLine("BN6 P/Invoke types: all three cells retain 28-byte widths, exact field offsets, names and pointer/ordinal distinctions.");
    }

    private static void Assert(bool condition) {
        if (!condition)
            throw new InvalidDataException("Binary Ninja changed a P/Invoke cell layout.");
    }
}
