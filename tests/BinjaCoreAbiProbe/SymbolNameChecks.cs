using System.Text;
using Atlas.Binja;

internal static class SymbolNameChecks {
    internal static void Run() {
        var cases = new (string Full, ulong Rva, string Short)[] {
            ("context::HytaleClient.Application.Program::Main", 0x8F9DC0, "context::Program::Main_008F9DC0"),
            ("context::called_by::HytaleClient.Application.Program::Main::00D031C0", 0xD031C0, "context::called_by::Program::Main_00D031C0"),
            ("context::reference_path::HytaleClient.Application.Program::Main::depth_4::002F4D60", 0x2F4D60, "context::reference_path::Program::Main_002F4D60"),
            ("context::between::First::and::Second::00001000", 0x1000, "context::between_00001000"),
            ("vtable::System.RuntimeType::slot_73", 0x1234, "vtable::RuntimeType::slot_73_00001234"),
            ("context::Example::" + new string('界', 20), 1, "context::Example::" + new string('界', 10) + "..._00000001"),
            ("context::System.Func`2<System.String,System.Object>::Invoke", 2, "context::Func`2::Invoke_00000002")
        };
        Span<byte> output = stackalloc byte[128];
        foreach (var item in cases) {
            int length = SymbolNames.Function(Encoding.UTF8.GetBytes(item.Full), item.Rva, output);
            if (Encoding.UTF8.GetString(output[..length]) != item.Short)
                throw new Exception($"Unexpected short name for {item.Full}");
        }

        if (!SymbolNames.IsDefault("sub_140001000"u8, 0x140001000)
            || !SymbolNames.IsDefault("j_context::ReflectedMethods::Fold"u8, 0x140001000)
            || !SymbolNames.IsDefault("data_140001000"u8, 0x140001000)
            || SymbolNames.IsDefault("ExitProcess"u8, 0x140001000)
            || SymbolNames.IsDefault("sub_140001000_suffix"u8, 0x140001000)
            || SymbolNames.IsDefault("sub_140001001"u8, 0x140001000))
            throw new Exception("Symbol precedence classification failed.");

        Console.WriteLine("Symbol names: compact provenance, distinct addresses, UTF-8 boundaries, and existing names preserved.");
    }
}
