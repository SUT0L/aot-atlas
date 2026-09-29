using System.Buffers.Binary;
using System.Diagnostics;
using System.Security.Cryptography;
using Atlas;

internal static class PInvokeScanChecks {
    internal static void Run(ReadOnlySpan<string> binaries) {
        foreach (string binary in binaries) {
            var image = new PeImage(File.ReadAllBytes(binary));
            var header = ReadyToRun.Read(image);
            var section = header.Find(313);
            var metadata = new Metadata(image.FileMemory(section.Start, checked((int)section.Length)),
                header.MetadataHandleBits, header.Major < 10);
            metadata.ReadDefinitions();
            var fixups = RuntimeTables.Fixups(image, header.Find(308));
            var maps = new ReflectionMaps();
            maps.Read(image, header, metadata, fixups, MapFormat.Auto);
            var extraction = new Extraction(image, header, metadata, maps, fixups);
            var original = extraction.PInvokes;
            string digest = Convert.ToHexStringLower(SHA256.HashData(image.FileData));
            if (original.Methods.Count == 0)
                throw new InvalidDataException("The supplied fixture has no lazy P/Invoke cells.");

            var empty = new PInvokeFixups(image, extraction.Types, new ReflectionMaps());
            Assert(empty.Methods.Count == 0 && empty.Modules.Count == 0);

            var method = original.Methods.First(entry => !entry.ByOrdinal);
            var module = original.Modules[method.Module];
            int methodOffset = image.FileRange(method.Address).Start;
            int moduleOffset = image.FileRange(module.Address).Start;
            for (int mutation = 0; mutation < 9; ++mutation) {
                byte[] bytes = (byte[])image.FileData.Clone();
                bool removeModule = mutation >= 4 && mutation <= 6;
                switch (mutation) {
                    case 0: bytes[methodOffset] = 1; break;
                    case 1: bytes[methodOffset + 24] = 1; break;
                    case 2: BinaryPrimitives.WriteUInt64LittleEndian(bytes.AsSpan(methodOffset + 8), 65536); break;
                    case 3: BinaryPrimitives.WriteUInt64LittleEndian(bytes.AsSpan(methodOffset + 16), module.CallingAssemblyType); break;
                    case 4: bytes[moduleOffset] = 1; break;
                    case 5: BinaryPrimitives.WriteUInt64LittleEndian(bytes.AsSpan(moduleOffset + 16), method.Address); break;
                    case 6: BinaryPrimitives.WriteUInt32LittleEndian(bytes.AsSpan(moduleOffset + 24), 1); break;
                    case 7: bytes[method.Name.Start] = 0xFF; break;
                    case 8: BinaryPrimitives.WriteUInt64LittleEndian(bytes.AsSpan(methodOffset + 8), 65535); break;
                }
                var changed = new PInvokeFixups(new PeImage(bytes), extraction.Types, maps);
                var expected = original.Methods.Where(entry => mutation == 8
                    || (removeModule ? entry.Module != method.Module
                    : mutation == 7 ? entry.ByOrdinal || entry.Name.Start != method.Name.Start
                    : entry.Address != method.Address)).Select(entry => entry.Address).ToHashSet();
                Assert(expected.SetEquals(changed.Methods.Select(entry => entry.Address)));
                Assert(changed.Modules.Count == changed.Methods.Select(entry => entry.Module).Distinct().Count());
                if (mutation == 8) {
                    var ordinal = changed.Methods.Single(entry => entry.Address == method.Address);
                    Assert(ordinal.ByOrdinal && ordinal.EntryPoint == 65535);
                }
            }

            // Isolate a real cell at the file-backed boundary
            // Its four tail padding bytes belong to the next allocation, not to the emitted fixup
            var boundary = new PeImage((byte[])image.FileData.Clone());
            int sectionIndex = boundary.FindSection(method.Address);
            var owner = boundary.Sections[sectionIndex];
            int cellOffset = (owner.FileSize - 32) & ~7;
            ulong cellAddress = image.ImageBase + owner.Rva + (uint)cellOffset;
            Assert(original.Methods.All(entry => entry.Address + 28 <= cellAddress));
            Assert(original.Modules.All(entry => entry.Address + 28 <= cellAddress));
            Assert(boundary.FindSection(method.EntryPoint) != sectionIndex && boundary.FindSection(module.NameAddress) != sectionIndex);
            image.FileData.AsSpan(moduleOffset, 28).CopyTo(boundary.FileData.AsSpan(owner.FileOffset + cellOffset));
            var orphan = new PInvokeFixups(boundary, extraction.Types, maps);
            Assert(orphan.Modules.Count == original.Modules.Count && orphan.Modules.All(entry => entry.Address != cellAddress));
            image.FileData.AsSpan(methodOffset, 28).CopyTo(boundary.FileData.AsSpan(owner.FileOffset + cellOffset));
            for (int tail = 27; tail <= 28; ++tail) {
                boundary.Sections[sectionIndex] = new PeSection(owner.Name, owner.Rva, owner.VirtualSize, owner.FileOffset,
                    cellOffset + tail, owner.Characteristics);
                var changed = new PInvokeFixups(boundary, extraction.Types, maps);
                Assert(changed.Methods.Any(entry => entry.Address == cellAddress) == (tail == 28));
            }

            double[] samples = new double[7];
            long allocated = 0;
            const int repetitions = 32;
            for (int sample = 0; sample < samples.Length; ++sample) {
                long before = GC.GetAllocatedBytesForCurrentThread();
                long start = Stopwatch.GetTimestamp();
                for (int repeat = 0; repeat < repetitions; ++repeat) {
                    var result = new PInvokeFixups(image, extraction.Types, maps);
                    Assert(result.Methods.Count == original.Methods.Count && result.Modules.Count == original.Modules.Count);
                }
                samples[sample] = Stopwatch.GetElapsedTime(start).TotalMilliseconds / repetitions;
                allocated = (GC.GetAllocatedBytesForCurrentThread() - before) / repetitions;
            }
            Array.Sort(samples);
            Console.WriteLine($"{digest}: {original.Methods.Count} methods, {original.Modules.Count} modules; mutation checks passed; "
                + $"decoder median {samples[3]:F4} ms ({samples[0]:F4}–{samples[^1]:F4}), {allocated} allocated bytes/call.");
        }
    }

    private static void Assert(bool condition) {
        if (!condition)
            throw new InvalidDataException("P/Invoke scan disagrees with the fixture mutation.");
    }
}
