using System.Buffers.Binary;
using System.Diagnostics;
using System.Security.Cryptography;
using Atlas;

internal static class DispatchResolutionChecks {
    internal static void Run(ReadOnlySpan<string> arguments) {
        const ulong start = 0x140001000;
        var uses = Decode("4C8D1D1000000041FF13C3").DispatchCellUses;
        Assert(uses.SequenceEqual([new DispatchCellUse(start, start + 7, start + 23)]));
        Assert(Decode("4C8D1D100000004531DB41FF13C3").DispatchCellUses.Count == 0);
        Assert(Decode("4C8D1D1000000041B30041FF13C3").DispatchCellUses.Count == 0);
        Assert(Decode("4C8D1D10000000750041FF13C3").DispatchCellUses.Count == 0);
        Assert(Decode("4C8D1D10000000E80000000041FF13C3").DispatchCellUses.Count == 0);
        Assert(Decode("4C8D1D100000006441FF13C3").DispatchCellUses.Count == 0);
        Assert(Decode("4C8D1D1000000041FF13C3", [start, start + 7]).DispatchCellUses.Count == 0);
        Assert(Decode("4C8D1D1000000041FF23").DispatchCellUses.Count == 1);
        Assert(Decode("4C8D1D1000000031C041FF13C3").DispatchCellUses.Count == 1);
        Assert(Decode("4C8D151000000041FF12C3").DispatchCellUses.SequenceEqual([
            new DispatchCellUse(start, start + 7, start + 23, 10)]));
        Assert(Decode("4C8D15100000004531D241FF12C3").DispatchCellUses.Count == 0);

        foreach (string binary in arguments) {
            var image = new PeImage(File.ReadAllBytes(binary));
            var rtr = ReadyToRun.Read(image);
            var section = rtr.Find(313);
            var metadata = new Metadata(section.Length == 0 ? default : image.FileMemory(section.Start, checked((int)section.Length)),
                rtr.MetadataHandleBits, rtr.Major < 10);
            metadata.ReadDefinitions();
            var fixups = RuntimeTables.Fixups(image, rtr.Find(308));
            var maps = new ReflectionMaps();
            maps.Read(image, rtr, metadata, fixups, MapFormat.Auto);
            var extraction = new Extraction(image, rtr, metadata, maps, fixups);
            var resolver = new DispatchResolver(extraction);
            var code = new CodeFlow(extraction, new ManagedAbi(extraction));
            var cells = new DispatchCells(extraction, code);
            Assert(cells.Cells.Count != 0);
            string audit = Path.ChangeExtension(binary, ".cells.bin");
            using (var writer = new BinaryWriter(File.Create(audit))) {
                writer.Write(SHA256.HashData(image.FileData));
                writer.Write(cells.Cells.Count);
                foreach (var cell in cells.Cells) {
                    writer.Write(checked((uint)(cell.Address - image.ImageBase)));
                    writer.Write(checked((uint)(extraction.Types.Types[cell.InterfaceType].Address - image.ImageBase)));
                    writer.Write(checked((uint)(cell.Terminator - image.ImageBase)));
                    writer.Write(cell.Slot);
                }
            }

            var startInfo = new ProcessStartInfo(binary) {
                RedirectStandardOutput = true, RedirectStandardError = true, UseShellExecute = false, CreateNoWindow = true
            };
            startInfo.ArgumentList.Add(Path.GetFullPath(audit));
            using var process = Process.Start(startInfo)!;
            string output = process.StandardOutput.ReadToEnd();
            string error = process.StandardError.ReadToEnd();
            process.WaitForExit();
            Assert(process.ExitCode == 0, error);
            string cellAudit = output.Split('\n').Single(line => line.StartsWith("C|", StringComparison.Ordinal));
            Assert(int.Parse(cellAudit.Split('|')[1]) == cells.Cells.Count);
            int matches = 0, missing = 0, ordering = 0;
            foreach (string line in output.Split('\n')) {
                if (!line.StartsWith("Q|", StringComparison.Ordinal))
                    continue;
                string[] parts = line.TrimEnd('\r').Split('|');
                ulong receiver = image.ImageBase + Convert.ToUInt64(parts[1], 16);
                ulong contract = image.ImageBase + Convert.ToUInt64(parts[2], 16);
                ushort slot = ushort.Parse(parts[3]);
                ulong live = Convert.ToUInt64(parts[5], 16);
                var result = resolver.Resolve(receiver, contract, slot);
                if (result.Status == DispatchResolutionStatus.UnknownRuntimeOrdering) {
                    ++ordering;
                } else if (live == 0) {
                    Assert(result.Status == DispatchResolutionStatus.NoBinding, line);
                    ++missing;
                } else {
                    Assert(result.Status is DispatchResolutionStatus.Resolved or DispatchResolutionStatus.RequiresInstantiation, line);
                    Assert(result.Target == image.ImageBase + (live & ~2UL), line);
                    ++matches;
                }
            }
            Assert(matches != 0 && missing != 0);
            Assert(resolver.Resolve(0, 0, 0).Status == DispatchResolutionStatus.UnknownType);

            if (cells.Uses.Count != 0) {
                var cell = cells.Cells.First(c => c.Uses.Count != 0);
                var only = new CodeFlow(image, [], new Dictionary<ulong, ulong>());
                only.DispatchCellUses.Add(cells.Uses[cell.Uses.Start]);
                int regionIndex = extraction.Memory.Find(cell.Address);
                var region = extraction.Memory.Regions[regionIndex];
                Assert(System.Runtime.InteropServices.MemoryMarshal.TryGetArray(region.Data, out ArraySegment<byte> storage));
                int offset = storage.Offset + (int)(cell.Address - region.Start);
                ulong encoded = BinaryPrimitives.ReadUInt64LittleEndian(storage.Array!.AsSpan(offset + 8));
                BinaryPrimitives.WriteUInt64LittleEndian(storage.Array.AsSpan(offset + 8), 0);
                Assert(new DispatchCells(extraction, only).Rejected.Single().Status == DispatchCellStatus.UnsupportedEncoding);
                BinaryPrimitives.WriteUInt64LittleEndian(storage.Array.AsSpan(offset + 8), encoded);
                Assert(new DispatchCells(extraction, only).Cells.Any(c => c.Address == cell.Address));

                var use = only.DispatchCellUses[0];
                only.DispatchCellUses[0] = use with { Cell = use.Cell + 8 };
                Assert(new DispatchCells(extraction, only).Rejected.Single().Status == DispatchCellStatus.Unaligned);
                only.DispatchCellUses[0] = use;
            }
            Console.WriteLine($"{Path.GetFileName(Path.GetDirectoryName(binary))}: {matches} live targets, {missing} absent bindings, "
                + $"{ordering} unresolved runtime orders, {cells.Cells.Count} live cells ({cellAudit.Trim()}), SHA256 {Convert.ToHexStringLower(SHA256.HashData(image.FileData))}.");
        }
        Console.WriteLine("Dispatch cells: direct/tail calls, register clobbers, segment addressing, call barriers, and incoming joins verified.");
    }

    private static CodeFlow Decode(string hex, ulong[]? roots = null) {
        var image = PeFixture.Create(Convert.FromHexString(hex), ".text", 0x60000020);
        return new CodeFlow(image, roots ?? [0x140001000], new Dictionary<ulong, ulong>());
    }

    private static void Assert(bool condition, string message = "Dispatch resolution check failed.") {
        if (!condition)
            throw new InvalidDataException(message);
    }
}
