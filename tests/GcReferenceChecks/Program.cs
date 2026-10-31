using System.ComponentModel;
using System.Buffers.Binary;
using System.Diagnostics;
using System.Reflection.PortableExecutable;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text.Json;

internal static unsafe class Program {
    private static readonly string[] Registers = [
        "rax", "rcx", "rdx", "rbx", "rsp", "rbp", "rsi", "rdi",
        "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15"
    ];

    private static int Main(string[] args) {
        try {
            if (args.Length < 4 || args[1] != "--cli") {
                throw new ArgumentException("Usage: GcReferenceChecks <native-library> --cli <aot-atlas executable or DLL> [mutation] <PE>...");
            }
            string cli = Path.GetFullPath(args[2]);
            var mutation = new Mutation();
            int inputStart = 3;
            if (args[inputStart] == "--inject-slot-offset-error") {
                mutation.SlotOffset = true;
                ++inputStart;
            } else if (args[inputStart] == "--inject-missing-chunk-start") {
                mutation.ChunkStart = true;
                ++inputStart;
            }
            Require(inputStart < args.Length, "At least one PE input is required.");
            Require(File.Exists(cli), $"CLI does not exist: {cli}");

            nint library = NativeLibrary.Load(Path.GetFullPath(args[0]));
            try {
                var abiVersion = (delegate* unmanaged[Cdecl]<uint>)NativeLibrary.GetExport(library, "gc_reference_abi_version");
                Equal(2U, abiVersion(), "native adapter ABI version");
                var current = (delegate* unmanaged[Cdecl]<byte*, uint, uint, OracleResult*, int>)NativeLibrary.GetExport(library, "gc_decode");
                var legacy = (delegate* unmanaged[Cdecl]<byte*, uint, uint, OracleResult*, int>)NativeLibrary.GetExport(library, "gc_decode_legacy");
                var batch = Stopwatch.StartNew();
                var totals = new Totals();
                for (int input = inputStart; input < args.Length; ++input) {
                    string path = Path.GetFullPath(args[input]);
                    CheckFile(cli, path, current, legacy, mutation, totals);
                }
                Require(!mutation.Requested || mutation.Applied, "Requested observation mutation had no eligible input.");
                Console.WriteLine($"GC reference batch: {totals.Methods:N0} methods, {totals.Samples:N0} sampled offsets, {totals.Slots:N0} declared slots; {batch.Elapsed.TotalSeconds:F3} s including CLI, JSON, native decoding and comparison.");
                Console.WriteLine($"Phases: CLI {totals.CliSeconds:F3} s, JSON {totals.JsonSeconds:F3} s, native {totals.NativeSeconds:F3} s, comparison {totals.CompareSeconds:F3} s; largest decoder workspace {totals.WorkspaceBytes:N0} B.");
            } finally {
                NativeLibrary.Free(library);
            }
            return 0;
        } catch (Exception error) when (error is InvalidDataException or IOException or JsonException or ArgumentException
            or Win32Exception or DllNotFoundException or EntryPointNotFoundException) {
            Console.Error.WriteLine(error.Message);
            return 1;
        }
    }

    private static void CheckFile(string cli, string path,
        delegate* unmanaged[Cdecl]<byte*, uint, uint, OracleResult*, int> current,
        delegate* unmanaged[Cdecl]<byte*, uint, uint, OracleResult*, int> legacy,
        Mutation mutation, Totals totals) {
        var elapsed = Stopwatch.StartNew();
        using var domain = new PeDomain(path);
        using JsonDocument document = ReadCliOutput(cli, path, totals);
        JsonElement root = document.RootElement;
        Equal("gcinfo", root.GetProperty("operation").GetString(), "operation");
        Equal(1, root.GetProperty("schema_version").GetInt32(), "schema version");
        Equal(Convert.ToHexStringLower(SHA256.HashData(domain.Bytes)), root.GetProperty("input_sha256").GetString(), "input SHA-256");
        var metadata = ReadImageMetadata(domain.Bytes);
        Equal(metadata.GcVersion, root.GetProperty("version").GetUInt32(), "GC version");
        Equal(metadata.ImageBase, root.GetProperty("image_base").GetUInt64(), "image base");
        Equal("complete", root.GetProperty("status").GetString(), "document status");
        string? regionSource = root.GetProperty("region_source").GetString();
        Require(!string.IsNullOrEmpty(regionSource) && regionSource != "Unknown", "CLI did not identify a managed region.");
        JsonElement methods = root.GetProperty("methods");
        Equal(domain.Methods.Length, methods.GetArrayLength(), "complete method count");

        ulong samples = 0;
        fixed (byte* bytes = domain.Bytes) {
            var decode = domain.NativeGcVersion < 4 ? legacy : current;
            for (int index = 0; index < domain.Methods.Length; ++index) {
                ReferenceMethod expected = domain.Methods[index];
                JsonElement method = methods[index];
                string location = $"{Path.GetFileName(path)} method 0x{expected.Begin:X}";
                Equal(expected.Begin, method.GetProperty("begin").GetUInt32(), $"{location}: ordered begin RVA");
                Equal(expected.End, method.GetProperty("end").GetUInt32(), $"{location}: end RVA");
                Equal(expected.GcAddress, method.GetProperty("gcinfo_rva").GetUInt32(), $"{location}: GC RVA");
                Equal("complete", method.GetProperty("status").GetString(), $"{location}: status");

                OracleResult oracle;
                long started = Stopwatch.GetTimestamp();
                int status = decode(bytes + expected.FileOffset, domain.NativeGcVersion, expected.End - expected.Begin, &oracle);
                totals.NativeSeconds += Stopwatch.GetElapsedTime(started).TotalSeconds;
                Require(status == 0, $"{location}: Microsoft decoder rejected PE method ({status}).");
                Require(oracle.BytesRead <= expected.BlobLength, $"{location}: Microsoft decoder exceeded bounded GC blob.");
                started = Stopwatch.GetTimestamp();
                CheckMethod(method, oracle, domain.NativeGcVersion, mutation, location, totals);
                totals.CompareSeconds += Stopwatch.GetElapsedTime(started).TotalSeconds;
                ++totals.Methods;
                totals.Samples += oracle.SampleCount;
                samples += oracle.SampleCount;
                totals.WorkspaceBytes = Math.Max(totals.WorkspaceBytes, oracle.WorkspaceBytes);
            }
        }
        Console.WriteLine($"{Path.GetFileName(path)}: {domain.Methods.Length:N0} methods, {samples:N0} sampled offsets, GCINFO v{metadata.GcVersion}; {elapsed.Elapsed.TotalSeconds:F3} s.");
    }

    private static (uint GcVersion, ulong ImageBase) ReadImageMetadata(byte[] bytes) {
        using var image = new PEReader(new MemoryStream(bytes, writable: false));
        uint version = 0;
        int matches = 0;
        foreach (SectionHeader section in image.PEHeaders.SectionHeaders) {
            if ((section.SectionCharacteristics & SectionCharacteristics.MemExecute) != 0) {
                continue;
            }
            ReadOnlySpan<byte> data = bytes.AsSpan(section.PointerToRawData, section.SizeOfRawData);
            for (int offset = 0; offset <= data.Length - 16; ++offset) {
                if (!data.Slice(offset, 4).SequenceEqual("RTR\0"u8)) {
                    continue;
                }
                int count = BinaryPrimitives.ReadUInt16LittleEndian(data[(offset + 12)..]);
                int rowSize = data[offset + 14];
                if (count == 0 || rowSize is not (16 or 24) || data[offset + 15] != 1
                    || count > (data.Length - offset - 16) / rowSize) {
                    continue;
                }
                int major = BinaryPrimitives.ReadUInt16LittleEndian(data[(offset + 4)..]);
                Require(major >= 9 && major < 21, $"RTR {major} is outside the pinned GCINFO decoder domain.");
                version = major >= 11 ? 4U : major == 10 ? 3U : 2U;
                ++matches;
            }
        }
        Equal(1, matches, "NativeAOT RTR header count");
        return (version, image.PEHeaders.PEHeader!.ImageBase);
    }

    private static JsonDocument ReadCliOutput(string cli, string input, Totals totals) {
        string directory = Path.Combine(Path.GetTempPath(), $"atlas-gc-cli-{Guid.NewGuid():N}");
        Directory.CreateDirectory(directory);
        try {
            string output = Path.Combine(directory, "gcinfo.json");
            var start = new ProcessStartInfo(cli.EndsWith(".dll", StringComparison.OrdinalIgnoreCase) ? "dotnet" : cli) {
                UseShellExecute = false,
                RedirectStandardOutput = true,
                RedirectStandardError = true
            };
            if (cli.EndsWith(".dll", StringComparison.OrdinalIgnoreCase)) {
                start.ArgumentList.Add(cli);
            }
            start.ArgumentList.Add("gcinfo");
            start.ArgumentList.Add(input);
            start.ArgumentList.Add(output);
            long started = Stopwatch.GetTimestamp();
            using var process = Process.Start(start)!;
            Task<string> stdout = process.StandardOutput.ReadToEndAsync();
            Task<string> stderr = process.StandardError.ReadToEndAsync();
            process.WaitForExit();
            string outputText = stdout.GetAwaiter().GetResult();
            string errorText = stderr.GetAwaiter().GetResult();
            totals.CliSeconds += Stopwatch.GetElapsedTime(started).TotalSeconds;
            Require(process.ExitCode == 0, $"CLI gcinfo failed for {input} (exit {process.ExitCode}).\n{errorText}{outputText}");
            started = Stopwatch.GetTimestamp();
            using var stream = File.OpenRead(output);
            JsonDocument result = JsonDocument.Parse(stream);
            totals.JsonSeconds += Stopwatch.GetElapsedTime(started).TotalSeconds;
            return result;
        } finally {
            Directory.Delete(directory, recursive: true);
        }
    }

    private static void CheckMethod(JsonElement method, OracleResult oracle, uint nativeVersion, Mutation mutation, string location, Totals totals) {
        CheckHeader(method, oracle, nativeVersion, location);
        JsonElement declared = method.GetProperty("slots");
        var slots = new Root[declared.GetArrayLength()];
        int untrackedCount = 0;
        for (int slot = 0; slot < slots.Length; ++slot) {
            JsonElement item = declared[slot];
            Equal(slot, item.GetProperty("index").GetInt32(), $"{location}: ordered slot index");
            uint flags = (item.GetProperty("interior").GetBoolean() ? 1U : 0U)
                | (item.GetProperty("pinned").GetBoolean() ? 2U : 0U)
                | (item.GetProperty("untracked").GetBoolean() ? 4U : 0U);
            if (item.TryGetProperty("register", out var register)) {
                Require(!item.TryGetProperty("stack_base", out _) && !item.TryGetProperty("stack_offset", out _), $"{location}: slot has register and stack location.");
                slots[slot] = new(RegisterIndex(register.GetString()), -1, 0, flags);
            } else {
                int stackBase = item.GetProperty("stack_base").GetString() switch {
                    "caller_sp" => 0,
                    "sp" => 1,
                    "frame_register" => 2,
                    _ => throw new InvalidDataException($"{location}: invalid stack base.")
                };
                slots[slot] = new(-1, stackBase, item.GetProperty("stack_offset").GetInt32(), flags);
                if (mutation.SlotOffset && !mutation.Applied) {
                    slots[slot] = slots[slot] with { Offset = checked(slots[slot].Offset + 8) };
                    mutation.Applied = true;
                }
            }
            if ((flags & 4) != 0) {
                ++untrackedCount;
            } else {
                Require(untrackedCount == 0, $"{location}: tracked slot follows untracked slot.");
            }
            for (int prior = 0; prior < slot; ++prior) {
                Require(slots[prior] != slots[slot], $"{location}: duplicate root declaration at slot {slot}.");
            }
        }
        totals.Slots += slots.Length;

        ReadOnlySpan<Root> roots = new(oracle.Roots, checked((int)oracle.RootCount));
        var rootSlots = new int[roots.Length];
        for (int root = 0; root < roots.Length; ++root) {
            rootSlots[root] = Array.IndexOf(slots, roots[root]);
            Require(rootSlots[root] >= 0, $"{location}: Microsoft root {roots[root]} has no CLI slot.");
        }
        Equal((uint)untrackedCount, oracle.UntrackedCount, $"{location}: untracked slot count");
        for (int index = 0; index < untrackedCount; ++index) {
            int slot = slots.Length - untrackedCount + index;
            Equal(slots[slot], roots[checked((int)oracle.Untracked[index])], $"{location}: ordered untracked root {index}");
        }

        JsonElement ranges = method.GetProperty("interruptible_ranges");
        JsonElement points = method.GetProperty("safepoints");
        JsonElement encodedTransitions = method.GetProperty("transitions");
        Equal(oracle.RangeCount, (uint)ranges.GetArrayLength(), $"{location}: interruptible range count");
        Equal(oracle.PointCount, (uint)points.GetArrayLength(), $"{location}: safepoint count");
        string liveness = oracle.PointCount != 0 ? "safepoints" : oracle.RangeCount != 0 ? "interruptible_ranges" : "untracked_only";
        Equal(liveness, method.GetProperty("liveness").GetString(), $"{location}: liveness kind");
        var transitions = new Transition[encodedTransitions.GetArrayLength()];
        for (int index = 0; index < transitions.Length; ++index) {
            JsonElement item = encodedTransitions[index];
            var transition = new Transition(item.GetProperty("offset").GetUInt32(), item.GetProperty("slot").GetInt32(),
                item.GetProperty("live").GetBoolean(), item.GetProperty("chunk_start").GetBoolean());
            Require((uint)transition.Slot < slots.Length && (slots[transition.Slot].Flags & 4) == 0,
                $"{location}: transition refers to an invalid tracked slot.");
            Require(transition.Offset < oracle.CodeLength && (index == 0 || transition.Offset >= transitions[index - 1].Offset),
                $"{location}: transition is out of order or outside code.");
            transitions[index] = transition;
        }

        // The native pointers belong to one reusable workspace and expire at the next decode.
        // Keep comparison here, while the corresponding CLI record is still available.
        var observed = new bool[slots.Length];
        var expected = new bool[slots.Length];
        int mismatches = 0;
        ReadOnlySpan<Event> events = new(oracle.Events, checked((int)oracle.EventCount));
        int transitionIndex = 0;
        int eventIndex = 0;
        ulong samples = 0;
        for (int range = 0; range < ranges.GetArrayLength(); ++range) {
            JsonElement pair = ranges[range];
            Equal(2, pair.GetArrayLength(), $"{location}: range arity");
            uint start = pair[0].GetUInt32();
            uint end = pair[1].GetUInt32();
            Equal(oracle.Ranges[range].Start, start, $"{location}: range start");
            Equal(oracle.Ranges[range].End, end, $"{location}: range end");
            for (uint offset = start; offset < end; ++offset) {
                ApplyTransitions(transitions, ref transitionIndex, offset, observed, expected, ref mismatches, mutation);
                ApplyOracleEvents(events, rootSlots, ref eventIndex, offset, expected, observed, ref mismatches);
                if (mismatches != 0) {
                    string difference = string.Join(", ", Enumerable.Range(0, slots.Length)
                        .Where(slot => observed[slot] != expected[slot])
                        .Select(slot => $"slot {slot} {slots[slot]} CLI={observed[slot]} Microsoft={expected[slot]}"));
                    throw new InvalidDataException($"{location}: live roots differ at interruptible byte {offset}: {difference}.");
                }
                ++samples;
            }
        }
        Require(transitionIndex == transitions.Length, $"{location}: transitions remain outside interruptible ranges.");
        for (int point = 0; point < points.GetArrayLength(); ++point) {
            JsonElement item = points[point];
            uint offset = item.GetProperty("offset").GetUInt32();
            Equal(oracle.Points[point], offset, $"{location}: ordered safepoint");
            for (int slot = 0; slot < observed.Length; ++slot) {
                SetLive(observed, expected, slot, false, ref mismatches);
            }
            JsonElement liveSlots = item.GetProperty("live_slots");
            int previous = -1;
            foreach (JsonElement liveSlot in liveSlots.EnumerateArray()) {
                int slot = liveSlot.GetInt32();
                Require(slot > previous && (uint)slot < slots.Length && (slots[slot].Flags & 4) == 0,
                    $"{location}: invalid ordered safepoint live slots.");
                SetLive(observed, expected, slot, true, ref mismatches);
                previous = slot;
            }
            ApplyOracleEvents(events, rootSlots, ref eventIndex, offset, expected, observed, ref mismatches);
            Require(mismatches == 0, $"{location}: live roots differ at safepoint {offset}.");
            ++samples;
        }
        Equal(oracle.EventCount, (uint)eventIndex, $"{location}: consumed native events");
        Equal(oracle.SampleCount, samples, $"{location}: complete sampled offset count");
    }

    private static void ApplyTransitions(Transition[] transitions, ref int index, uint offset,
        bool[] observed, bool[] expected, ref int mismatches, Mutation mutation) {
        while (index < transitions.Length && transitions[index].Offset <= offset) {
            Transition transition = transitions[index++];
            if (transition.ChunkStart && mutation.ChunkStart && !mutation.Applied
                && observed[transition.Slot] != transition.Live) {
                mutation.Applied = true;
                continue;
            }
            SetLive(observed, expected, transition.Slot, transition.Live, ref mismatches);
        }
    }

    private static void ApplyOracleEvents(ReadOnlySpan<Event> events, int[] rootSlots, ref int index, uint offset,
        bool[] expected, bool[] observed, ref int mismatches) {
        while (index < events.Length && events[index].Offset == offset) {
            Event change = events[index++];
            SetLive(expected, observed, rootSlots[change.Root], change.Live != 0, ref mismatches);
        }
    }

    private static void SetLive(bool[] state, bool[] other, int slot, bool live, ref int mismatches) {
        if (state[slot] == live) {
            return;
        }
        mismatches += state[slot] == other[slot] ? 1 : -1;
        state[slot] = live;
    }

    private static void CheckHeader(JsonElement method, OracleResult oracle, uint nativeVersion, string location) {
        Equal(oracle.CodeLength, method.GetProperty("code_length").GetUInt32(), $"{location}: code length");
        Equal(oracle.Outgoing, method.GetProperty("outgoing_stack_bytes").GetUInt32(), $"{location}: outgoing stack bytes");
        Equal(oracle.HeaderBytes, method.GetProperty("header_bytes").GetUInt32(), $"{location}: header bytes");
        Equal(oracle.ReturnKind, OptionalInt(method, "return_kind", -1), $"{location}: return kind");
        Equal(oracle.StackBase, method.TryGetProperty("frame_register", out var frame) ? RegisterIndex(frame.GetString()) : -1, $"{location}: frame register");
        Equal(oracle.Cookie, OptionalInt(method, "cookie_caller_sp_offset", -1), $"{location}: cookie slot");
        Equal(oracle.GenericContext, OptionalInt(method, "generic_context_stack_offset", -1), $"{location}: generic context slot");
        Equal(oracle.ReversePInvoke, OptionalInt(method, "reverse_pinvoke_stack_offset", -1), $"{location}: reverse P/Invoke slot");
        Equal(oracle.Psp, OptionalInt(method, "psp_initial_sp_offset", -1), $"{location}: PSP slot");
        Equal(oracle.EditAndContinue, method.TryGetProperty("edit_and_continue_bytes", out var enc) ? enc.GetUInt32() : 0U, $"{location}: edit and continue bytes");
        uint flags = method.GetProperty("flags").GetUInt32();
        Require((flags & ~0x3ffU) == 0, $"{location}: unknown header flags.");
        Equal(oracle.IsVarArg != 0, (flags & 1) != 0, $"{location}: vararg flag");
        Equal(oracle.GenericContextKind, (flags & 0x30) >> 4, $"{location}: generic context kind flag");
        Equal(oracle.Cookie != -1, (flags & 4) != 0, $"{location}: cookie presence flag");
        Equal(oracle.GenericContext != -1, (flags & 0x30) != 0, $"{location}: generic context presence flag");
        Equal(oracle.HasStackBase != 0, (flags & 0x40) != 0, $"{location}: frame register presence flag");
        Equal(oracle.ReversePInvoke != -1, (flags & 0x200) != 0, $"{location}: reverse P/Invoke presence flag");
        Equal(oracle.Psp != -1, (flags & 8) != 0, $"{location}: PSP presence flag");
        Equal(oracle.EditAndContinuePresent != 0, (flags & 0x100) != 0, $"{location}: edit and continue flag");
        Equal((flags & 0x100) != 0, method.TryGetProperty("edit_and_continue_bytes", out _), $"{location}: edit and continue presence flag");
        Equal((flags & 2) != 0, method.TryGetProperty("security_object_stack_offset", out _), $"{location}: security object presence flag");
        // Current-format AMD64 returns true unconditionally; only the legacy
        // public getter distinguishes the encoded report-only-leaf bit.
        if (nativeVersion < 4) {
            Equal(oracle.WantsReportOnlyLeaf != 0, (flags & 0x80) != 0, $"{location}: report-only-leaf flag");
        }
        if (oracle.Cookie != -1) {
            JsonElement range = method.GetProperty("cookie_valid_range");
            Equal(2, range.GetArrayLength(), $"{location}: cookie range arity");
            Equal(oracle.ValidStart, range[0].GetUInt32(), $"{location}: cookie valid start");
            Equal(oracle.ValidEnd, range[1].GetUInt32(), $"{location}: cookie valid end");
        } else {
            Require(!method.TryGetProperty("cookie_valid_range", out _), $"{location}: unexpected cookie valid range.");
        }
        string headerBase = oracle.StackBase < 0 ? "sp" : "frame_register";
        if (oracle.GenericContext != -1) {
            Equal(headerBase, method.GetProperty("generic_context_stack_base").GetString(), $"{location}: generic context base");
            Equal(oracle.ValidStart, method.GetProperty("generic_context_valid_from").GetUInt32(), $"{location}: generic valid start");
            string kind = oracle.GenericContextKind switch { 1 => "method_table", 2 => "method_descriptor", _ => "this" };
            Equal(kind, method.GetProperty("generic_context_kind").GetString(), $"{location}: generic context kind");
        } else {
            Require(!method.TryGetProperty("generic_context_stack_base", out _) && !method.TryGetProperty("generic_context_valid_from", out _)
                && !method.TryGetProperty("generic_context_kind", out _), $"{location}: unexpected generic context fields.");
        }
        if (oracle.ReversePInvoke != -1) {
            Equal(headerBase, method.GetProperty("reverse_pinvoke_stack_base").GetString(), $"{location}: reverse P/Invoke base");
        } else {
            Require(!method.TryGetProperty("reverse_pinvoke_stack_base", out _), $"{location}: unexpected reverse P/Invoke base.");
        }
    }

    private static int OptionalInt(JsonElement item, string name, int absent) => item.TryGetProperty(name, out var value) ? value.GetInt32() : absent;

    private static int RegisterIndex(string? name) {
        int register = Array.IndexOf(Registers, name);
        Require(register >= 0, $"Unknown register: {name}");
        return register;
    }

    private static void Equal<T>(T expected, T observed, string field) {
        Require(EqualityComparer<T>.Default.Equals(expected, observed), $"{field}: expected {expected}, observed {observed}.");
    }

    private static void Require(bool condition, string message) {
        if (!condition) {
            throw new InvalidDataException(message);
        }
    }

    private sealed class Mutation {
        internal bool SlotOffset;
        internal bool ChunkStart;
        internal bool Applied;
        internal bool Requested => SlotOffset || ChunkStart;
    }

    private sealed class Totals {
        internal long Methods;
        internal ulong Samples;
        internal long Slots;
        internal double CliSeconds;
        internal double JsonSeconds;
        internal double NativeSeconds;
        internal double CompareSeconds;
        internal ulong WorkspaceBytes;
    }

    [StructLayout(LayoutKind.Sequential)]
    private readonly record struct Root(int Register, int Base, int Offset, uint Flags);
    private readonly record struct Transition(uint Offset, int Slot, bool Live, bool ChunkStart);

    [StructLayout(LayoutKind.Sequential)]
    private readonly struct Range {
        internal readonly uint Start;
        internal readonly uint End;
    }

    [StructLayout(LayoutKind.Sequential)]
    private readonly struct Event {
        internal readonly uint Offset;
        internal readonly uint Root;
        internal readonly uint Live;
    }

    [StructLayout(LayoutKind.Sequential)]
    // ABI v2: keep this layout synchronized with bridge.cpp's Result.
    private struct OracleResult {
        internal uint CodeLength;
        internal uint Outgoing;
        internal uint ValidStart;
        internal uint ValidEnd;
        internal int StackBase;
        internal int Cookie;
        internal int GenericContext;
        internal int ReversePInvoke;
        internal int Psp;
        internal uint EditAndContinue;
        internal uint HeaderBytes;
        internal uint BytesRead;
        internal uint RootCount;
        internal uint RangeCount;
        internal uint PointCount;
        internal uint EventCount;
        internal uint UntrackedCount;
        internal int ReturnKind;
        internal uint GenericContextKind;
        internal uint HasStackBase;
        internal uint IsVarArg;
        internal uint WantsReportOnlyLeaf;
        internal uint EditAndContinuePresent;
        internal ulong SampleCount;
        internal ulong WorkspaceBytes;
        internal Root* Roots;
        internal Range* Ranges;
        internal uint* Points;
        internal Event* Events;
        internal uint* Untracked;
    }
}
