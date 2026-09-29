using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text.Json;

internal static unsafe partial class Program {
    private static int completed;

    [StructLayout(LayoutKind.Sequential)]
    private struct RuntimeClause {
        public uint Kind, TryStart, TryEnd;
        public nint Filter, Handler, Type;
    }

    [LibraryImport("kernel32.dll")]
    private static partial nint GetModuleHandleW(nint name);

    [LibraryImport("*", EntryPoint = "RhFindMethodStartAddress"), SuppressGCTransition]
    private static partial nint FindMethodStart(nint address);

    [LibraryImport("*", EntryPoint = "RhGetTargetOfUnboxingAndInstantiatingStub"), SuppressGCTransition]
    private static partial nint UnboxingTarget(nint address);

    [LibraryImport("*", EntryPoint = "?GetRuntimeInstance@@YAPEAVRuntimeInstance@@XZ"), SuppressGCTransition]
    private static partial nint RuntimeInstance();

    [LibraryImport("*", EntryPoint = "?GetCodeManagerForAddress@RuntimeInstance@@QEAAPEAVICodeManager@@PEAX@Z"), SuppressGCTransition]
    private static partial nint CodeManager(nint runtime, nint address);

    [LibraryImport("*", EntryPoint = "?FindMethodInfo@CoffNativeCodeManager@@UEAA_NPEAXPEAVMethodInfo@@@Z"), SuppressGCTransition]
    private static partial byte FindMethodInfo(nint manager, nint address, byte* info);

    [LibraryImport("*", EntryPoint = "?EHEnumInit@CoffNativeCodeManager@@UEAA_NPEAVMethodInfo@@PEAPEAXPEAVEHEnumState@@@Z"), SuppressGCTransition]
    private static partial byte EnumInit(nint manager, byte* info, out nint methodStart, byte* state);

    [LibraryImport("*", EntryPoint = "?EHEnumNext@CoffNativeCodeManager@@UEAA_NPEAVEHEnumState@@PEAUEHClause@@@Z"), SuppressGCTransition]
    private static partial byte EnumNext(nint manager, byte* state, RuntimeClause* clause);

    private static void Main(string[] args) {
        using var document = JsonDocument.Parse(File.ReadAllBytes(args[0]));
        var expected = document.RootElement;
        string digest = Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(Environment.ProcessPath!))).ToLowerInvariant();
        Assert(expected.GetProperty("input_sha256").GetString() == digest);
        var exceptions = expected.GetProperty("exceptions").EnumerateArray().ToDictionary(blob => blob.GetProperty("rva").GetUInt32());
        nint module = GetModuleHandleW(0);
        nint runtime = RuntimeInstance();
        nint manager = CodeManager(runtime, module + expected.GetProperty("frames")[0].GetProperty("begin").GetInt32());
        Assert(module != 0 && runtime != 0 && manager != 0 && sizeof(RuntimeClause) == 40);

        Span<byte> methodInfo = stackalloc byte[88], enumState = stackalloc byte[40];
        methodInfo.Fill(0xA5);
        enumState.Fill(0xA5);
        int lookups = 0, clauseCount = 0, associated = 0, methods = 0;
        fixed (byte* info = methodInfo)
        fixed (byte* state = enumState) {
            foreach (var frame in expected.GetProperty("frames").EnumerateArray()) {
                uint begin = frame.GetProperty("begin").GetUInt32(), end = frame.GetProperty("end").GetUInt32();
                nint root = module + (nint)frame.GetProperty("root").GetUInt32();
                for (int sample = 0; sample < 3; ++sample) {
                    uint pc = sample == 0 ? begin : sample == 1 ? begin + (end - begin) / 2 : end - 1;
                    Assert(FindMethodStart(module + (nint)pc) == root);
                    ++lookups;
                }
                uint target = frame.GetProperty("unboxing_target").GetUInt32();
                Assert(UnboxingTarget(module + (nint)begin) == (target == 0 ? 0 : module + (nint)target));
                if (target != 0)
                    ++associated;

                byte[] header = Convert.FromHexString(frame.GetProperty("header_bytes").GetString()!);
                var liveHeader = new ReadOnlySpan<byte>((void*)(module + (nint)frame.GetProperty("trailer_rva").GetUInt32()), header.Length);
                Assert(liveHeader.SequenceEqual(header));
                if (frame.GetProperty("kind").GetString() != "root")
                    continue;

                ++methods;
                Assert(FindMethodInfo(manager, module + (nint)begin, info) != 0);
                bool hasExceptions = EnumInit(manager, info, out nint methodStart, state) != 0;
                uint exceptionAddress = frame.GetProperty("exception_info").GetUInt32();
                Assert(hasExceptions == (exceptionAddress != 0));
                if (hasExceptions) {
                    Assert(methodStart == root);
                    foreach (var clause in exceptions[exceptionAddress].GetProperty("clauses").EnumerateArray()) {
                        RuntimeClause actual = default;
                        Assert(EnumNext(manager, state, &actual) != 0);
                        string kind = clause.GetProperty("kind").GetString()!;
                        Assert(actual.Kind == (kind == "typed" ? 0 : kind == "filter" ? 2 : 1));
                        Assert(actual.TryStart == clause.GetProperty("try_start").GetUInt32());
                        Assert(actual.TryEnd == clause.GetProperty("try_end").GetUInt32());
                        Assert(actual.Handler == root + (nint)clause.GetProperty("handler_offset").GetUInt32());
                        if (kind == "typed")
                            Assert(actual.Type == module + (nint)clause.GetProperty("type_rva").GetUInt32());
                        if (kind == "filter")
                            Assert(actual.Filter == root + (nint)clause.GetProperty("filter_offset").GetUInt32());
                        ++clauseCount;
                    }
                    RuntimeClause terminal = default;
                    Assert(EnumNext(manager, state, &terminal) == 0);
                }
                Assert(!methodInfo[72..].ContainsAnyExcept((byte)0xA5));
                Assert(!enumState[24..].ContainsAnyExcept((byte)0xA5));
            }
        }

        foreach (var blob in exceptions.Values) {
            byte[] bytes = Convert.FromHexString(blob.GetProperty("bytes").GetString()!);
            var actual = new ReadOnlySpan<byte>((void*)(module + (nint)blob.GetProperty("rva").GetUInt32()), bytes.Length);
            Assert(actual.SequenceEqual(bytes));
        }

        Assert(Guard(0) + Guard(1) + Guard(2) == 81 && completed == 3);
        delegate* unmanaged<int, int> callback = &Reverse;
        Assert(callback(7) == 14);
        var value = new GenericValue<string> { Value = "probe" };
        Func<int, string> bound = value.Describe;
        Assert(bound(3) == "probe3");
        Console.WriteLine($"{methods} methods, {lookups} runtime root lookups, {clauseCount} runtime EH clauses, {associated} unboxing targets matched; {digest}");
    }

    [MethodImpl(MethodImplOptions.NoInlining)]
    private static int Guard(int value) {
        try {
            if (value == 1)
                throw new InvalidOperationException();
            if (value == 2)
                throw new ArgumentException();
            return 20;
        } catch (InvalidOperationException) {
            return 30;
        } catch (ArgumentException) when (value == 2) {
            return 31;
        } finally {
            ++completed;
        }
    }

    private struct GenericValue<T> {
        public T Value;

        [MethodImpl(MethodImplOptions.NoInlining)]
        public string Describe(int suffix) => Value!.ToString() + suffix;
    }

    [UnmanagedCallersOnly]
    private static int Reverse(int value) => value * 2;

    private static void Assert(bool condition) {
        if (!condition)
            throw new InvalidDataException("Extracted exception metadata disagrees with the live NativeAOT runtime.");
    }
}
