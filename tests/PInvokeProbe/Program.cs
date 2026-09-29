using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text.Json;

internal static unsafe class Program {
    private const string Provider = "AtlasPInvokeProvider.dll";
    private const string UnicodeProvider = "AtlasPInvoke_λ.dll";
    private const string LongEntryPoint = "LongEntryPoint_01234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789";

    [DllImport(Provider, EntryPoint = "A", ExactSpelling = true)]
    private static extern int Single(int value);

    [DllImport(Provider, EntryPoint = "Add", ExactSpelling = true)]
    private static extern int Add(int left, int right);

    [DllImport(Provider, EntryPoint = "#7", ExactSpelling = true)]
    private static extern int Ordinal(int value);

    [DllImport(Provider, EntryPoint = "#0", ExactSpelling = true)]
    private static extern int MissingOrdinal();

    [DllImport(Provider, EntryPoint = LongEntryPoint, ExactSpelling = true)]
    private static extern int LongName(int value);

    [DllImport(UnicodeProvider, EntryPoint = "A", ExactSpelling = true)]
    private static extern int UnicodeModule(int value);

    [DllImport(Provider, EntryPoint = "A", CharSet = CharSet.Ansi, ExactSpelling = false)]
    private static extern int Ansi(int value);

    [DllImport(Provider, EntryPoint = "U", CharSet = CharSet.Unicode, ExactSpelling = false)]
    private static extern int Unicode(int value);

    [DllImport("kernel32.dll", ExactSpelling = true)]
    private static extern nint GetModuleHandleW(nint name);

    [DllImport("kernel32.dll", ExactSpelling = true)]
    private static extern nint GetProcAddress(nint module, nint ordinal);

    private static void Main(string[] args) {
        using var document = JsonDocument.Parse(File.ReadAllBytes(args[0]));
        var expected = document.RootElement;
        string digest = Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(Environment.ProcessPath!))).ToLowerInvariant();
        Assert(digest == expected.GetProperty("input_sha256").GetString());
        Assert(Single(9) == 10 && Add(7, 8) == 15 && Ordinal(9) == 27 && LongName(5) == 6);
        Assert(UnicodeModule(17) == 18 && Ansi(20) == 21 && Unicode(30) == 130);
        string missing = "";
        try {
            MissingOrdinal();
        } catch (EntryPointNotFoundException) { missing = nameof(EntryPointNotFoundException); }
        catch (NullReferenceException) { missing = nameof(NullReferenceException); }
        Assert(missing.Length != 0);

        nint image = GetModuleHandleW(0);
        ulong originalBase = expected.GetProperty("image_base").GetUInt64();
        var modules = expected.GetProperty("modules");
        int verified = 0;
        foreach (var method in expected.GetProperty("methods").EnumerateArray()) {
            var module = modules[method.GetProperty("module_index").GetInt32()];
            string moduleName = module.GetProperty("module").GetString()!;
            if (moduleName != Provider && moduleName != UnicodeProvider)
                continue;

            byte* cell = (byte*)image + (method.GetProperty("address").GetUInt64() - originalBase);
            byte* moduleCell = (byte*)image + (module.GetProperty("address").GetUInt64() - originalBase);
            Assert(*(byte**)(cell + 16) == moduleCell && *(uint*)(cell + 24) == method.GetProperty("flags").GetUInt32());
            Assert(*(uint*)(moduleCell + 24) == module.GetProperty("search_path").GetUInt32());
            Assert(*(byte**)(moduleCell + 8) == (byte*)image + (module.GetProperty("name_address").GetUInt64() - originalBase));
            Assert(*(byte**)(moduleCell + 16) == (byte*)image + (module.GetProperty("calling_assembly_type").GetUInt64() - originalBase));
            Assert(Marshal.PtrToStringUTF8(*(nint*)(moduleCell + 8)) == moduleName);
            var assemblyType = Type.GetTypeFromHandle(RuntimeTypeHandle.FromIntPtr(*(nint*)(moduleCell + 16)))!;
            Assert(assemblyType.FullName == "<Module>" && assemblyType.Assembly == typeof(Program).Assembly);
            nint handle = *(nint*)moduleCell;
            Assert(handle != 0);

            nint target;
            if (method.TryGetProperty("ordinal", out var ordinal)) {
                int value = ordinal.GetInt32();
                Assert(*(nuint*)(cell + 8) == (uint)value);
                target = GetProcAddress(handle, value);
                Assert((target == 0) == (value == 0));
            } else {
                string name = method.GetProperty("name").GetString()!;
                Assert(*(byte**)(cell + 8) == (byte*)image + (method.GetProperty("entry_point").GetUInt64() - originalBase));
                Assert(Marshal.PtrToStringUTF8(*(nint*)(cell + 8)) == name);
                target = NativeLibrary.GetExport(handle, name == "U" ? "UW" : name);
            }
            Assert(*(nint*)cell == target);
            ++verified;
        }
        Assert(verified == 8);
        Console.WriteLine($"{verified} lazy P/Invoke cells match resolved targets, module identities, names, ordinals and flags; missing ordinal reports {missing}; {digest}");
    }

    private static void Assert(bool condition) {
        if (!condition)
            throw new InvalidDataException("P/Invoke metadata disagrees with the loaded module or its resolved entrypoint.");
    }
}
