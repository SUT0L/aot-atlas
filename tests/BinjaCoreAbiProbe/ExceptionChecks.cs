using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using Atlas;
using Atlas.Binja;

internal static unsafe class ExceptionChecks {
    internal static void Run(ReadOnlySpan<string> binaries) {
        byte empty = 0;
        BoolConfidence unsigned = new() { Confidence = 255 }, signed = new() { Value = 1, Confidence = 255 };
        nint u8 = Core.BNCreateIntegerType(1, &unsigned, &empty);
        nint u32 = Core.BNCreateIntegerType(4, &unsigned, &empty);
        nint i32 = Core.BNCreateIntegerType(4, &signed, &empty);
        (string Name, ulong Offset, ulong Width, bool Signed)[][] expected = [
            [("flags", 0, 1, false)],
            [("flags", 0, 1, false), ("eh_info_rva", 1, 4, true)],
            [("flags", 0, 1, false), ("associated_data_rva", 1, 4, false)],
            [("flags", 0, 1, false), ("associated_data_rva", 1, 4, false), ("eh_info_rva", 5, 4, true)],
            [("flags", 0, 1, false)],
            [("flags", 0, 1, false), ("unboxing_target_rel32", 1, 4, true)]
        ];
        uint[] widths = [1, 5, 5, 9, 1, 5];
        for (int key = 0; key < expected.Length; ++key) {
            nint original = key < 4 ? ExceptionTypes.Header(key, u8, u32, i32) : ExceptionTypes.Associated(key - 4, u8, i32);
            nint type = Core.BNNewTypeReference(original);
            Core.BNFreeType(original);
            Assert(Core.BNGetTypeWidth(type) == widths[key]);
            nint structure = Inspect.BNGetTypeStructure(type);
            Assert(Inspect.BNIsStructurePacked(structure) != 0);
            nuint count = 0;
            var members = Inspect.BNGetStructureMembers(structure, &count);
            Assert(count == (uint)expected[key].Length);
            for (int i = 0; i < (int)count; ++i) {
                var member = members[i];
                var field = expected[key][i];
                Assert(Marshal.PtrToStringUTF8(member.Name) == field.Name && member.Offset == field.Offset);
                Assert(Core.BNGetTypeWidth(member.Type) == field.Width && Inspect.BNGetTypeClass(member.Type) == 2);
                var sign = Inspect.BNIsTypeSigned(member.Type);
                Assert(sign.Value == (field.Signed ? 1 : 0) && sign.Confidence == 255);
            }
            Inspect.BNFreeStructureMemberList(members, count);
            Core.BNFreeStructure(structure);
            Core.BNFreeType(type);
        }
        Core.BNFreeType(i32);
        Core.BNFreeType(u32);
        Console.WriteLine("BN6 exception types: all six header layouts retain exact widths, field names, offsets and signedness.");

        Span<double> totalTimes = stackalloc double[5], managedTimes = stackalloc double[5], textTimes = stackalloc double[5];
        Span<double> arrays = stackalloc double[5], cachedArrays = stackalloc double[5];
        Span<byte> text = stackalloc byte[256];
        foreach (string binary in binaries) {
            var image = new PeImage(File.ReadAllBytes(binary));
            var unwind = new UnwindTables(image);
            var contributions = new PeDebug(image);
            var managed = new ManagedUnwind(image, unwind, contributions);
            long allocated = 0;
            if (!GC.TryStartNoGCRegion(256 * 1024 * 1024))
                throw new InvalidOperationException("Unable to isolate the parser allocation measurement.");
            try {
                for (int sample = 0; sample < totalTimes.Length; ++sample) {
                    long before = GC.GetAllocatedBytesForCurrentThread();
                    long start = Stopwatch.GetTimestamp();
                    var result = new ManagedUnwind(image, unwind, contributions);
                    managedTimes[sample] = Stopwatch.GetElapsedTime(start).TotalMilliseconds;
                    allocated = GC.GetAllocatedBytesForCurrentThread() - before;
                    Assert(result.Frames.Length == managed.Frames.Length && result.Clauses.Length == managed.Clauses.Length);

                    start = Stopwatch.GetTimestamp();
                    var whole = new ManagedUnwind(image, new UnwindTables(image), new PeDebug(image));
                    totalTimes[sample] = Stopwatch.GetElapsedTime(start).TotalMilliseconds;
                    Assert(whole.Frames.Length == managed.Frames.Length && whole.Clauses.Length == managed.Clauses.Length);
                }
            } finally {
                GC.EndNoGCRegion();
            }

            long outputBytes = 0;
            if (!GC.TryStartNoGCRegion(4 * 1024 * 1024))
                throw new InvalidOperationException("Unable to isolate the tag allocation measurement.");
            try {
                long before = GC.GetAllocatedBytesForCurrentThread();
                for (int sample = 0; sample < textTimes.Length; ++sample) {
                    long start = Stopwatch.GetTimestamp();
                    long bytes = 0;
                    foreach (ref readonly var frame in managed.Frames.AsSpan()) {
                        var function = unwind.Entries[frame.Entry - 1].Function;
                        uint root = unwind.Entries[managed.Frames[frame.Root - 1].Entry - 1].Function.Begin;
                        uint eh = frame.ExceptionInfo == 0 ? 0 : managed.Exceptions[frame.ExceptionInfo - 1].Address;
                        bytes += ExceptionText.Frame(text, managed.RegionSource, frame, function, root, eh);
                    }
                    foreach (ref readonly var clause in managed.Clauses.AsSpan())
                        bytes += ExceptionText.Clause(text, managed.RegionSource, clause);
                    textTimes[sample] = Stopwatch.GetElapsedTime(start).TotalMilliseconds;
                    outputBytes = bytes;
                }
                Assert(GC.GetAllocatedBytesForCurrentThread() == before);
            } finally {
                GC.EndNoGCRegion();
            }
            totalTimes.Sort();
            managedTimes.Sort();
            textTimes.Sort();
            int arrayShapes = 0;
            var element = new TypeConfidence(u8);
            for (int sample = 0; sample < arrays.Length; ++sample) {
                long start = Stopwatch.GetTimestamp();
                foreach (ref readonly var blob in managed.Exceptions.AsSpan()) {
                    nint type = Core.BNCreateArrayType(&element, blob.Length);
                    if (sample == 0)
                        Assert(Core.BNGetTypeWidth(type) == blob.Length);
                    Core.BNFreeType(type);
                }
                arrays[sample] = Stopwatch.GetElapsedTime(start).TotalMilliseconds;

                start = Stopwatch.GetTimestamp();
                var cache = new Dictionary<uint, nint>(managed.Exceptions.Length);
                foreach (ref readonly var blob in managed.Exceptions.AsSpan()) {
                    if (!cache.TryGetValue(blob.Length, out nint type)) {
                        type = Core.BNCreateArrayType(&element, blob.Length);
                        cache.Add(blob.Length, type);
                    }
                    if (sample == 0)
                        Assert(Core.BNGetTypeWidth(type) == blob.Length);
                }
                foreach (nint type in cache.Values)
                    Core.BNFreeType(type);
                cachedArrays[sample] = Stopwatch.GetElapsedTime(start).TotalMilliseconds;
                arrayShapes = cache.Count;
            }
            arrays.Sort();
            cachedArrays.Sort();
            string digest = Convert.ToHexStringLower(SHA256.HashData(image.FileData));
            Console.WriteLine($"Exceptions {digest}: {managed.Frames.Length} frames, {managed.Exceptions.Length} EH blobs, {managed.Clauses.Length} clauses; Windows + managed parse {totalTimes[2]:F3} ms, managed parse {managedTimes[2]:F3} ms/{allocated} allocated bytes; {outputBytes} tag bytes {textTimes[2]:F3} ms/0 allocated bytes.");
            Console.WriteLine($"EH blob arrays: {managed.Exceptions.Length} uncached {arrays[2]:F3} ms; {arrayShapes} cached shapes {cachedArrays[2]:F3} ms.");
        }
        Core.BNFreeType(u8);
    }

    private static void Assert(bool condition) {
        if (!condition)
            throw new InvalidDataException("NativeAOT exception representation disagrees with its format.");
    }
}
