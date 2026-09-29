using System.Collections;
using System.Diagnostics.CodeAnalysis;
using System.Runtime.InteropServices;
using System.Security.Cryptography;

Print(typeof(List<int>), typeof(IList));
Print(typeof(Dictionary<string, int>), typeof(IDictionary));
Print(typeof(System.Collections.Specialized.StringCollection), typeof(IList));
Print(typeof(MemoryStream), typeof(IDisposable));
Print(typeof(System.IO.Compression.DeflateStream), typeof(IAsyncDisposable));

if (args.Length == 1)
    Audit(args[0]);

static unsafe void Print([DynamicallyAccessedMembers(DynamicallyAccessedMemberTypes.PublicMethods | DynamicallyAccessedMemberTypes.NonPublicMethods)] Type type,
    [DynamicallyAccessedMembers(DynamicallyAccessedMemberTypes.PublicMethods | DynamicallyAccessedMemberTypes.NonPublicMethods)] Type contract) {
    nint image = Native.GetModuleHandleW(0);
    var map = type.GetInterfaceMap(contract);

    for (int i = 0; i < map.InterfaceMethods.Length; ++i) {
        Console.WriteLine($"I|{type.TypeHandle.Value - image:X}|{contract.TypeHandle.Value - image:X}|{map.InterfaceMethods[i].Name}");

#if !NET8_0
        nint pointer = map.TargetMethods[i].MethodHandle.GetFunctionPointer();
        if ((pointer & 2) != 0)
            pointer = *(nint*)(pointer - 2);

        Console.WriteLine($"M|{type.TypeHandle.Value - image:X}|{contract.TypeHandle.Value - image:X}|{map.InterfaceMethods[i].Name}|{pointer - image:X}|{map.TargetMethods[i].Name}");
#endif
    }
}

static unsafe void Audit(string path) {
    using var reader = new BinaryReader(File.OpenRead(path));
    byte[] digest = SHA256.HashData(File.ReadAllBytes(Environment.ProcessPath!));
    if (!reader.ReadBytes(32).AsSpan().SequenceEqual(digest))
        throw new InvalidDataException("Audit input does not match this executable.");

    byte* image = (byte*)Native.GetModuleHandleW(0);
    int peOffset = *(int*)(image + 0x3C);
    uint imageSize = *(uint*)(image + peOffset + 24 + 56);
    int count = reader.ReadInt32();
    int matches = 0;

    for (int i = 0; i < count; ++i) {
        uint rva = reader.ReadUInt32();
        uint length = reader.ReadUInt32();
        uint expected = reader.ReadUInt32();
        if (rva >= imageSize || length > imageSize - rva)
            throw new InvalidDataException("Audit range exceeds the loaded image.");

        uint hash = 2166136261;
        for (uint offset = 0; offset < length; ++offset)
            hash = unchecked((hash ^ image[rva + offset]) * 16777619);

        if (hash != expected)
            throw new InvalidDataException($"Live bytes differ at RVA 0x{rva:X}.");

        ++matches;
    }

    int queries = reader.ReadInt32();
    for (int i = 0; i < queries; ++i) {
        uint type = reader.ReadUInt32();
        uint contract = reader.ReadUInt32();
        ushort slot = reader.ReadUInt16();
        if (type >= imageSize || contract >= imageSize)
            throw new InvalidDataException("Dispatch query exceeds the loaded image.");

#if NET8_0
        // A non-null context selects static dispatch in this runtime
        nint target = Native.ResolveDispatch((nint)(image + type), (nint)(image + contract), slot, null);
#else
        nint target = Native.ResolveDispatch((nint)(image + type), (nint)(image + contract), slot);
#endif
        if (target == 0)
            throw new InvalidDataException($"The runtime did not resolve dispatch for type 0x{type:X}, interface 0x{contract:X}, slot {slot}.");

        Console.WriteLine($"R|{type:X}|{contract:X}|{slot}|{target - (nint)image:X}");
    }

    if (reader.BaseStream.Position != reader.BaseStream.Length)
        throw new InvalidDataException("Audit has trailing bytes.");

    Console.WriteLine($"A|{matches}");
}

internal static partial class Native {
    [LibraryImport("kernel32.dll")]
    internal static partial nint GetModuleHandleW(nint name);

    [LibraryImport("__Internal", EntryPoint = "RhResolveDispatchOnType")]
    [SuppressGCTransition]
#if NET8_0
    internal static unsafe partial nint ResolveDispatch(nint type, nint contract, ushort slot, nint* context);
#else
    internal static partial nint ResolveDispatch(nint type, nint contract, ushort slot);
#endif
}
