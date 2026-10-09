using System.Buffers.Binary;
using Atlas;

internal static class ShortTailcallChecks {
    private const ulong ImageBase = 0x140000000;
    private const ulong Context = ImageBase + 0x2000;
    private const ulong Pointer = Context + 18;

    internal static void Run() {
        int cases = 0;

        ContextCase(0, [0xEB, 20], 1);
        ContextCase(128, [0xEB, 0x94], 1);
        ContextCase(0, [0xE9, 17, 0, 0, 0], 1);
        ContextCase(0, [0xE8, 17, 0, 0, 0, 0xC3], 1);
        ContextCase(0, [0x2E, 0xEB, 19], 1);
        ContextCase(0, [0xC3, 0xEB, 19], 0);
        ContextCase(0, [0xEB], 0);
        ContextCase(0, [0xEB, 21], 0);
        ContextCase(0, [0xEB, 0xFE], 0);
        ContextCase(0, [0xE9, 17, 0, 0], 0);
        ContextCase(0, [0x48, 0xB8, 0xEB, 18, 0, 0, 0, 0, 0, 0, 0xC3], 0);

        DelegateCase(0, [0xEB, 62], 1);
        DelegateCase(128, [0xEB, 0xBE], 1);
        DelegateCase(0, [0xE9, 59, 0, 0, 0], 1);
        DelegateCase(0, [0xE8, 59, 0, 0, 0, 0xC3], 1);
        DelegateCase(0, [0x2E, 0xEB, 61], 1);
        DelegateCase(0, [0xC3, 0xEB, 61], 0);
        DelegateCase(0, [0xEB], 0);
        DelegateCase(0, [0xEB, 63], 0);
        DelegateCase(0, [0xEB, 0xFE], 0);
        DelegateCase(0, [0xE9, 59, 0, 0], 0);
        DelegateCase(0, [0x48, 0xB8, 0xEB, 60, 0, 0, 0, 0, 0, 0, 0xC3], 0);

        Console.WriteLine($"Short tailcalls: {cases} public context/delegate cases passed, including backward, final-byte, unreachable, truncated and embedded-opcode branches.");

        void ContextCase(int offset, byte[] branch, int expected) {
            byte[] code = new byte[10 + branch.Length];
            code[0] = 0x48;
            code[1] = 0xB9;
            BinaryPrimitives.WriteUInt64LittleEndian(code.AsSpan(2), Context);
            branch.CopyTo(code, 10);

            var fixture = Create(offset, code);
            var result = new GenericContextReferences(fixture.Image, fixture.Unwind, fixture.Map);

            Assert(result.Values.Count == expected
                && result.Values.All(value => value.Target == ImageBase + 0x1020 && value.Context == Context),
                $"Context tailcall case {cases} disagrees with the hand-derived target.");
            ++cases;
        }

        void DelegateCase(int offset, byte[] code, int expected) {
            var fixture = Create(offset, code);
            var result = new FatFunctionPointers(
                fixture.Image, fixture.Header, new RuntimeMemory(fixture.Image, default),
                fixture.Unwind, fixture.Map, [new(ImageBase + 0x10C0, 8)]);

            Assert(result.Values.Count == expected && result.References.Count == expected
                && result.References.All(value => value.Source == FatPointerSource.DelegateInitializer
                    && value.Owner == ImageBase + 0x1000 + (uint)offset)
                && result.Values.All(value => value.Pointer == Pointer
                    && value.Body == ImageBase + 0x1020 && value.Context == Context),
                $"Delegate tailcall case {cases} disagrees with the hand-derived descriptor.");
            ++cases;
        }
    }

    private static (PeImage Image, ReadyToRun Header, UnwindTables Unwind, MethodGcMap Map) Create(
        int callerOffset, byte[] code) {
        byte[] bytes = new byte[1024];
        "MZ"u8.CopyTo(bytes);
        BinaryPrimitives.WriteUInt32LittleEndian(bytes.AsSpan(60), 64);
        "PE\0\0"u8.CopyTo(bytes.AsSpan(64));
        BinaryPrimitives.WriteUInt16LittleEndian(bytes.AsSpan(68), 0x8664);
        BinaryPrimitives.WriteUInt16LittleEndian(bytes.AsSpan(70), 2);
        BinaryPrimitives.WriteUInt16LittleEndian(bytes.AsSpan(84), 240);
        BinaryPrimitives.WriteUInt16LittleEndian(bytes.AsSpan(88), 0x20B);
        BinaryPrimitives.WriteUInt64LittleEndian(bytes.AsSpan(112), ImageBase);
        BinaryPrimitives.WriteUInt32LittleEndian(bytes.AsSpan(144), 0x3000);
        BinaryPrimitives.WriteUInt32LittleEndian(bytes.AsSpan(148), 512);
        BinaryPrimitives.WriteUInt32LittleEndian(bytes.AsSpan(196), 16);
        BinaryPrimitives.WriteUInt32LittleEndian(bytes.AsSpan(224), 0x2060);
        BinaryPrimitives.WriteUInt32LittleEndian(bytes.AsSpan(228), 60);

        ".managed"u8.CopyTo(bytes.AsSpan(328));
        ".rdata"u8.CopyTo(bytes.AsSpan(368));

        for (int index = 0; index < 2; ++index) {
            var row = bytes.AsSpan(328 + index * 40, 40);
            BinaryPrimitives.WriteUInt32LittleEndian(row[8..], 256);
            BinaryPrimitives.WriteUInt32LittleEndian(row[12..], (uint)(0x1000 + index * 0x1000));
            BinaryPrimitives.WriteUInt32LittleEndian(row[16..], 256);
            BinaryPrimitives.WriteUInt32LittleEndian(row[20..], (uint)(512 + index * 256));
            BinaryPrimitives.WriteUInt32LittleEndian(row[36..], index == 0 ? 0x60000020U : 0x40000040U);
        }

        var text = bytes.AsSpan(512, 256);
        text.Fill(0xC3);
        new byte[] { 0x48, 0x89, 0x4C, 0x24, 32, 0xC3 }.CopyTo(text[32..]);

        text[64] = 0x4C;
        text[65] = 0x8D;
        text[66] = 0x05;
        BinaryPrimitives.WriteInt32LittleEndian(text[67..], checked((int)(Pointer - ImageBase - 0x1047)));
        new byte[] { 0x4C, 0x8D, 0x0D, 114, 0, 0, 0, 0xE9, 109, 0, 0, 0 }.CopyTo(text[71..]);
        code.CopyTo(text[callerOffset..]);

        var data = bytes.AsSpan(768, 256);
        BinaryPrimitives.WriteUInt64LittleEndian(data[16..], ImageBase + 0x1020);
        BinaryPrimitives.WriteUInt64LittleEndian(data[24..], Context);
        "RTR\0"u8.CopyTo(data[64..]);
        BinaryPrimitives.WriteUInt16LittleEndian(data[68..], 18);
        BinaryPrimitives.WriteUInt16LittleEndian(data[70..], 4);
        BinaryPrimitives.WriteUInt16LittleEndian(data[76..], 1);
        data[78] = 16;
        data[79] = 1;
        BinaryPrimitives.WriteUInt32LittleEndian(data[80..], 999);
        BinaryPrimitives.WriteUInt32LittleEndian(data[84..], 8);
        BinaryPrimitives.WriteUInt64LittleEndian(data[88..], Context);

        uint[] begin = [0x1000, 0x1020, 0x1040, 0x1080, 0x10C0];
        uint[] end = [0x1020, 0x1040, 0x1060, 0x10A0, 0x10C1];

        for (int index = 0; index < begin.Length; ++index) {
            var row = data[(96 + index * 12)..];
            BinaryPrimitives.WriteUInt32LittleEndian(row, begin[index]);
            BinaryPrimitives.WriteUInt32LittleEndian(row[4..], end[index]);
            BinaryPrimitives.WriteUInt32LittleEndian(row[8..], (uint)(0x20C0 + index * 8));
            data[192 + index * 8] = 1;
        }

        var image = new PeImage(bytes);
        var header = ReadyToRun.Read(image);
        var unwind = new UnwindTables(image);
        var managed = new ManagedUnwind(image, unwind, null);
        var map = new MethodGcMap(image, header, unwind, managed);

        // These fixtures isolate code evidence from GC bit encoding, tested separately.
        // The saved RCX slot and logical extents are declared independently of the analysis.
        for (int index = 0; index < map.Methods.Length; ++index) {
            MethodGcInfo? info = index == (callerOffset == 0 ? 0 : 3)
                ? new MethodGcInfo { CodeLength = (uint)code.Length }
                : null;

            if (index == 1) {
                info = new MethodGcInfo {
                    Flags = 0x20,
                    CodeLength = 6,
                    ValidRangeStart = 5,
                    ValidRangeEnd = 6,
                    GenericContextSlot = 32
                };
            }

            map.Methods[index] = map.Methods[index] with { Info = info, Error = null };
        }

        return (image, header, unwind, map);
    }

    private static void Assert(bool condition, string message) {
        if (!condition)
            throw new Exception(message);
    }
}
