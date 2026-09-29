using System.Buffers.Binary;
using System.Diagnostics;
using System.Security.Cryptography;
using Atlas;
using Iced.Intel;

internal static class RuntimeHelperChecks {
    internal static void Run(ReadOnlySpan<string> binaries) {
        foreach (string binary in binaries) {
            var extraction = Extract(File.ReadAllBytes(binary));
            var code = new CodeFlow(extraction, new ManagedAbi(extraction));
            long start = Stopwatch.GetTimestamp();
            var helpers = new RuntimeHelpers(extraction, code);
            double seconds = Stopwatch.GetElapsedTime(start).TotalSeconds;
            Assert(helpers.Status == RuntimeHelperStatus.Complete);
            Assert(helpers.TableCount is 12 or 14 && helpers.Helpers.Length == (helpers.TableCount == 14 ? 8 : 7));
            Assert(extraction.Types.Types[extraction.Types.Index[helpers.ArrayType]].ElementType == 0x16);
            Assert(helpers.StartupPath.Length != 0);
            foreach (var helper in helpers.Helpers) {
                Assert(extraction.Image.IsExecutable(helper.Address));
                Assert(BinaryPrimitives.ReadUInt64LittleEndian(extraction.Image.FileSpan(helper.Cell, 8)) == helper.Address);
            }

            // The reserved slot and array-return identity are independent parts of the bootstrap contract; neither may be silently disregarded
            if (extraction.Image.FileData.Length < 4_000_000) {
                var owner = extraction.Unwind.Entries.Take(extraction.Unwind.DirectoryCount)
                    .Single(e => helpers.Registration >= extraction.Image.ImageBase + e.Function.Begin
                        && helpers.Registration < extraction.Image.ImageBase + e.Function.End).Function;
                ulong begin = extraction.Image.ImageBase + owner.Begin;
                var file = extraction.Image.FileRange(begin);
                var decoder = Decoder.Create(64, new ByteArrayCodeReader(extraction.Image.FileData, file.Start, (int)(owner.End - owner.Begin)));
                decoder.IP = begin;
                ulong previousCall = 0, resultCheck = 0;
                while (decoder.IP < helpers.Registration) {
                    decoder.Decode(out var instruction);
                    if (instruction.FlowControl == FlowControl.Call) {
                        previousCall = instruction.IP;
                        resultCheck = 0;
                    } else if (previousCall != 0 && instruction.Mnemonic == Mnemonic.Test && instruction.Length == 2
                        && instruction.Op0Register == Register.AL && instruction.Op1Register == Register.AL) {
                        resultCheck = instruction.IP;
                    }
                }
                Assert(resultCheck != 0);
                byte[] interrupted = (byte[])extraction.Image.FileData.Clone();
                int resultOffset = extraction.Image.FileRange(resultCheck).Start;
                interrupted[resultOffset] = 0xFF;
                interrupted[resultOffset + 1] = 0xD0;
                var interruptedExtraction = Extract(interrupted);
                var interruptedCode = new CodeFlow(interruptedExtraction, new ManagedAbi(interruptedExtraction));
                var interruptedHelpers = new RuntimeHelpers(interruptedExtraction, interruptedCode);
                Assert(interruptedHelpers.Status != RuntimeHelperStatus.Complete && interruptedHelpers.Helpers.Length == 0);

                foreach (ulong address in new[] { helpers.Table + 32, helpers.Table + 40 }) {
                    byte[] changed = (byte[])extraction.Image.FileData.Clone();
                    int offset = extraction.Image.FileRange(address).Start;
                    BinaryPrimitives.WriteUInt64LittleEndian(changed.AsSpan(offset), helpers.Helpers[0].Address);
                    var altered = Extract(changed);
                    var alteredCode = new CodeFlow(altered, new ManagedAbi(altered));
                    var rejected = new RuntimeHelpers(altered, alteredCode);
                    Assert(rejected.Status != RuntimeHelperStatus.Complete && rejected.Helpers.Length == 0);
                }
            }
            Console.WriteLine($"{Path.GetFileName(binary)} {Convert.ToHexStringLower(SHA256.HashData(extraction.Image.FileData))}: "
                + $"{helpers.Helpers.Length} classlib helpers, {helpers.TableCount} slots, {seconds * 1000:F3} ms.");
        }
    }

    private static Extraction Extract(byte[] data) {
        var image = new PeImage(data);
        var header = ReadyToRun.Read(image);
        var section = header.Find(313);
        var metadata = new Metadata(image.FileMemory(section.Start, checked((int)section.Length)), header.MetadataHandleBits, header.Major < 10);
        metadata.ReadDefinitions();
        var fixups = RuntimeTables.Fixups(image, header.Find(308));
        var maps = new ReflectionMaps();
        maps.Read(image, header, metadata, fixups);
        return new Extraction(image, header, metadata, maps, fixups);
    }

    private static void Assert(bool condition) {
        if (!condition)
            throw new Exception("Runtime helper assertion failed.");
    }
}
