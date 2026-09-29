using System.Globalization;
using System.Runtime.InteropServices;
using Iced.Intel;

namespace Atlas;

public enum CodeRelation : byte { None, FuncletOf, CalledBy, AddressReferencedBy, Calls, Between }

public struct ContextFunction {
    public ulong Address, Witness;
    public int Origin, Parent, Second, Depth;
    public CodeRelation Relation;
}

internal readonly record struct ContextEdge(ulong Witness, int To, CodeRelation Relation);

public sealed class CodeContext {
    public readonly CodeOrigins Origins;
    public readonly ContextFunction[] Functions = [];
    public readonly int Count;
    public readonly int UnownedCallSites, UnownedAddressSites;
    public readonly int UnprovenAddressSites;

    public CodeContext() { Origins = new(); }

    public CodeContext(Extraction extraction, ManagedAbi abi, CodeFlow code) {
        Origins = new CodeOrigins(extraction, abi, code.Runtime);
        var image = extraction.Image;
        var addresses = new List<ulong>(checked(code.Entrypoints.Length + code.Calls.Count + Origins.Values.Count));
        addresses.AddRange(code.Entrypoints);
        foreach (var edge in code.Calls) {
            if (image.IsExecutable(edge.Target))
                addresses.Add(edge.Target);
        }
        foreach (var origin in Origins.Values)
            addresses.Add(origin.Address);
        addresses.Sort();
        int count = 0;
        for (int i = 0; i < addresses.Count; ++i) {
            if (count == 0 || addresses[i] != addresses[count - 1])
                addresses[count++] = addresses[i];
        }
        addresses.RemoveRange(count, addresses.Count - count);

        Functions = new ContextFunction[checked(count + 1)];
        var index = new Dictionary<ulong, int>(count);
        for (int i = 0; i < count; ++i) {
            Functions[i + 1].Address = addresses[i];
            index.Add(addresses[i], i + 1);
        }
        int[] queue = new int[count];
        int queued = 0;
        for (int i = 0; i < Origins.Values.Count; ++i) {
            int function = index[Origins.Values[i].Address];
            Functions[function].Origin = i + 1;
            queue[queued++] = function;
        }

        var directory = CollectionsMarshal.AsSpan(extraction.Unwind.Entries)[..extraction.Unwind.DirectoryCount];
        var reader = new ByteArrayCodeReader(image.FileData);
        var decoder = Decoder.Create(64, reader);
        var owners = new (int From, int To)[checked(code.Calls.Count + code.Addresses.Count)];
        var forward = new (int Start, int Count)[Functions.Length];
        var reverse = new (int Start, int Count)[Functions.Length];
        for (int kind = 0; kind < 2; ++kind) {
            var input = kind == 0 ? CollectionsMarshal.AsSpan(code.Calls) : CollectionsMarshal.AsSpan(code.Addresses);
            int first = kind == 0 ? 0 : code.Calls.Count;
            int row = 0;
            ulong start = 0, end = 0, previousEnd = 0;
            for (int i = 0; i < input.Length; ++i) {
                ref readonly var edge = ref input[i];
                if (!index.TryGetValue(edge.Target, out int target))
                    continue;
                // Each input is ordered by instruction address
                // A single sweep proves containment without assigning gaps to the nearest name
                while (row < directory.Length && image.ImageBase + directory[row].Function.Begin <= edge.Instruction) {
                    var range = directory[row++].Function;
                    ulong next = image.ImageBase + range.Begin;
                    if (next != start) {
                        previousEnd = Math.Max(previousEnd, end);
                        start = next;
                        end = 0;
                    }
                    end = Math.Max(end, image.ImageBase + range.End);
                }
                if (start == 0 || edge.Instruction >= end || edge.Instruction < previousEnd) {
                    if (kind == 0)
                        ++UnownedCallSites;
                    else
                        ++UnownedAddressSites;
                    continue;
                }
                if (kind != 0) {
                    // An immediate integer can equal a function address
                    // Memory addressing supplies a stronger witness for this relation
                    reader.Position = image.FileRange(edge.Instruction).Start;
                    decoder.IP = edge.Instruction;
                    decoder.Decode(out var instruction);
                    if (!instruction.IsIPRelativeMemoryOperand) {
                        ++UnprovenAddressSites;
                        continue;
                    }
                }
                int source = index[start];
                if (source == target)
                    continue;
                owners[first + i] = (source, target);
                ++forward[source].Count;
                if (kind == 0)
                    ++reverse[target].Count;
            }
        }

        foreach (ref readonly var frame in extraction.Managed.Frames.AsSpan()) {
            var child = extraction.Unwind.Entries[frame.Entry - 1];
            var root = extraction.Unwind.Entries[extraction.Managed.Frames[frame.Root - 1].Entry - 1];
            if (root.Function.Begin != child.Function.Begin)
                ++forward[index[image.ImageBase + root.Function.Begin]].Count;
        }

        int edgeCount = 0;
        for (int direction = 0; direction < 2; ++direction) {
            var ranges = direction == 0 ? forward : reverse;
            for (int i = 1; i < ranges.Length; ++i) {
                int length = ranges[i].Count;
                ranges[i] = (edgeCount, 0);
                edgeCount = checked(edgeCount + length);
            }
        }
        var links = new ContextEdge[edgeCount];
        // The source tables already order witnesses
        // Scatter each relation in priority order to retain deterministic traversal without sorting edges
        foreach (ref readonly var frame in extraction.Managed.Frames.AsSpan()) {
            var child = extraction.Unwind.Entries[frame.Entry - 1];
            var root = extraction.Unwind.Entries[extraction.Managed.Frames[frame.Root - 1].Entry - 1];
            if (root.Function.Begin == child.Function.Begin)
                continue;
            ref var range = ref forward[index[image.ImageBase + root.Function.Begin]];
            links[range.Start + range.Count++] = new ContextEdge(image.ImageBase + child.Address,
                index[image.ImageBase + child.Function.Begin], CodeRelation.FuncletOf);
        }
        for (int kind = 0; kind < 2; ++kind) {
            var input = kind == 0 ? CollectionsMarshal.AsSpan(code.Calls) : CollectionsMarshal.AsSpan(code.Addresses);
            int first = kind == 0 ? 0 : code.Calls.Count;
            var relation = kind == 0 ? CodeRelation.CalledBy : CodeRelation.AddressReferencedBy;
            for (int i = 0; i < input.Length; ++i) {
                var owner = owners[first + i];
                if (owner.From == 0)
                    continue;
                ref var range = ref forward[owner.From];
                links[range.Start + range.Count++] = new ContextEdge(input[i].Instruction, owner.To, relation);
                if (kind == 0) {
                    ref var backward = ref reverse[owner.To];
                    links[backward.Start + backward.Count++] = new ContextEdge(input[i].Instruction, owner.From, CodeRelation.Calls);
                }
            }
        }

        for (int direction = 0; direction < 2; ++direction) {
            var ranges = direction == 0 ? forward : reverse;
            if (direction != 0) {
                queued = 0;
                for (int i = 1; i < Functions.Length; ++i) {
                    if (Functions[i].Origin != 0)
                        queue[queued++] = i;
                }
            }

            for (int position = 0; position < queued; ++position) {
                int parent = queue[position];
                var range = ranges[parent];
                foreach (ref readonly var edge in links.AsSpan(range.Start, range.Count)) {
                    ref var child = ref Functions[edge.To];
                    if (child.Origin != 0)
                        continue;
                    child.Origin = Functions[parent].Origin;
                    child.Parent = parent;
                    child.Depth = checked(Functions[parent].Depth + 1);
                    child.Relation = edge.Relation;
                    child.Witness = edge.Witness;
                    queue[queued++] = edge.To;
                    ++Count;
                }
            }
        }

        // Proximity describes PE layout, never a declaring type
        // Only bounded gaps between two named runtime-function entries receive this label
        int left = -1;
        for (int row = 0; row < directory.Length; ++row) {
            int right = index[image.ImageBase + directory[row].Function.Begin];
            if (Functions[right].Origin == 0 || Functions[right].Depth != 0)
                continue;
            if (left >= 0 && row - left <= 20) {
                int parent = index[image.ImageBase + directory[left].Function.Begin];
                for (int middle = left + 1; middle < row; ++middle) {
                    ref var function = ref Functions[index[image.ImageBase + directory[middle].Function.Begin]];
                    if (function.Origin != 0)
                        continue;
                    function.Origin = Functions[parent].Origin;
                    function.Parent = parent;
                    function.Second = right;
                    function.Relation = CodeRelation.Between;
                    function.Depth = 1;
                    function.Witness = image.ImageBase + directory[middle].Address;
                    ++Count;
                }
            }
            left = row;
        }

        var used = new bool[Origins.Values.Count];
        foreach (ref readonly var function in Functions.AsSpan()) {
            if (function.Depth == 0)
                continue;
            used[function.Origin - 1] = true;
            if (function.Second != 0)
                used[Functions[function.Second].Origin - 1] = true;
        }
        Origins.Render(extraction, code.Runtime, used);
    }

    public static string RelationName(CodeRelation relation) => relation switch {
        CodeRelation.FuncletOf => "funclet_of",
        CodeRelation.CalledBy => "called_by",
        CodeRelation.AddressReferencedBy => "address_referenced_by",
        CodeRelation.Calls => "calls",
        CodeRelation.Between => "between",
        _ => throw new ArgumentOutOfRangeException(nameof(relation))
    };

    public int WriteName(in ContextFunction function, ulong imageBase, Span<char> destination) {
        "context::".CopyTo(destination);
        int length = 9;
        string relation = function.Depth == 1 ? RelationName(function.Relation) : "reference_path";
        relation.CopyTo(destination[length..]);
        length += relation.Length;
        "::".CopyTo(destination[length..]);
        length += 2;
        var name = Origins.Values[function.Origin - 1].Name;
        Origins.Text.Span.Slice(name.Start, name.Count).CopyTo(destination[length..]);
        length += name.Count;
        if (function.Second != 0) {
            "::and::".CopyTo(destination[length..]);
            length += 7;
            name = Origins.Values[Functions[function.Second].Origin - 1].Name;
            Origins.Text.Span.Slice(name.Start, name.Count).CopyTo(destination[length..]);
            length += name.Count;
        }
        if (function.Depth > 1) {
            "::depth_".CopyTo(destination[length..]);
            length += 8;
            function.Depth.TryFormat(destination[length..], out int depth, provider: CultureInfo.InvariantCulture);
            length += depth;
        }
        "::".CopyTo(destination[length..]);
        length += 2;
        (function.Address - imageBase).TryFormat(destination[length..], out int digits, "X8", CultureInfo.InvariantCulture);
        return length + digits;
    }
}
