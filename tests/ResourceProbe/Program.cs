using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text.Json;

internal static partial class Program {
    private static unsafe void Main() {
        _ = typeof(PayloadMarker).Assembly.GetManifestResourceNames();
        nint image = GetModuleHandleW(0);
        using var json = new Utf8JsonWriter(Console.OpenStandardOutput());
        json.WriteStartObject();
        json.WriteString("input_sha256", Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(Environment.ProcessPath!))).ToLowerInvariant());
        json.WriteStartArray("resources");
        foreach (var assembly in AppDomain.CurrentDomain.GetAssemblies()) {
            foreach (string name in assembly.GetManifestResourceNames()) {
                using var stream = assembly.GetManifestResourceStream(name);
                if (stream is not UnmanagedMemoryStream memory)
                    throw new Exception("The NativeAOT resource stream is not backed by native memory.");

                var data = new ReadOnlySpan<byte>(memory.PositionPointer, checked((int)memory.Length));
                json.WriteStartObject();
                json.WriteString("assembly", assembly.GetName().FullName);
                json.WriteString("name", name);
                json.WriteNumber("rva", (long)memory.PositionPointer - (long)image);
                json.WriteNumber("length", data.Length);
                json.WriteBase64String("data", data);
                json.WriteEndObject();
            }
        }
        json.WriteEndArray();
        json.WriteEndObject();
    }

    [LibraryImport("kernel32", EntryPoint = "GetModuleHandleW")]
    private static partial nint GetModuleHandleW(nint name);
}
