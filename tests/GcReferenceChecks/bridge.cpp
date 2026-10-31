#include "common.h"
#include "gcinfodecoder.h"

#include <algorithm>
#include <cstdio>
#include <cstdlib>
#include <vector>

struct Root {
    int32_t reg;
    int32_t base;
    int32_t offset;
    uint32_t flags;

    bool operator==(const Root& other) const {
        return reg == other.reg && base == other.base
            && offset == other.offset && flags == other.flags;
    }
};

struct Range {
    uint32_t start;
    uint32_t end;
};

struct Event {
    uint32_t offset;
    uint32_t root;
    uint32_t live;
};

// ABI v2: keep this layout synchronized with Program.OracleResult.
struct Result {
    uint32_t codeLength;
    uint32_t outgoing;
    uint32_t validStart;
    uint32_t validEnd;
    int32_t stackBase;
    int32_t cookie;
    int32_t genericContext;
    int32_t reversePInvoke;
    int32_t psp;
    uint32_t editAndContinue;
    uint32_t headerBytes;
    uint32_t bytesRead;
    uint32_t rootCount;
    uint32_t rangeCount;
    uint32_t pointCount;
    uint32_t eventCount;
    uint32_t untrackedCount;
    int32_t returnKind;
    uint32_t genericContextKind;
    uint32_t hasStackBase;
    uint32_t isVarArg;
    uint32_t wantsReportOnlyLeaf;
    uint32_t editAndContinuePresent;
    uint64_t sampleCount;
    uint64_t workspaceBytes;
    Root* roots;
    Range* ranges;
    uint32_t* points;
    Event* events;
    uint32_t* untracked;
};

// One sequential batch owns this workspace. Result pointers survive until the
// next gc_decode call; vector capacities are reused across methods and files.
struct Workspace {
    std::vector<Root> roots;
    std::vector<Range> ranges;
    std::vector<uint32_t> points;
    std::vector<uint32_t> current;
    std::vector<uint32_t> previous;
    std::vector<uint32_t> untracked;
    std::vector<Event> events;
    uintptr_t registers[16];
    REGDISPLAY display;
    uint32_t bytesRead;
    uint32_t reportFlags;
};

static Workspace workspace;

static void ReportRoot(void*, OBJECTREF* object, uint32_t flags) {
    uintptr_t address = (uintptr_t)object;
    Root root{-1, -1, 0, flags | workspace.reportFlags};

    for (int reg = 0; reg < 16; ++reg) {
        if (address == (uintptr_t)&workspace.registers[reg]) {
            root.reg = reg;
            break;
        }
    }

    if (root.reg == -1) {
        for (int base = 0; base < 3; ++base) {
            uintptr_t value = base == 0 ? 0 : (uintptr_t)base << 40;
            intptr_t delta = (intptr_t)(address - value);
            if (delta >= INT32_MIN && delta <= INT32_MAX) {
                root.base = base;
                root.offset = (int32_t)delta;
                break;
            }
        }
        if (root.base == -1) {
            std::fputs("Microsoft decoder reported an unrecognized root address.\n", stderr);
            std::abort();
        }
    }

    auto found = std::find(workspace.roots.begin(), workspace.roots.end(), root);
    uint32_t id = (uint32_t)(found - workspace.roots.begin());
    if (found == workspace.roots.end()) {
        workspace.roots.push_back(root);
    }
    workspace.current.push_back(id);
}

static bool ReportRange(uint32_t start, uint32_t end, void*) {
    workspace.ranges.push_back({start, end});
    return false;
}

static void ReportPoint(GcInfoDecoder*, uint32_t offset, void*) {
    workspace.points.push_back(offset);
}

static void RecordBytesRead(GcInfoDecoder& decoder) {
    workspace.bytesRead = std::max(workspace.bytesRead, (uint32_t)decoder.GetNumBytesRead());
}

static void Sample(GCInfoToken token, uint32_t offset, bool safePoint = false) {
    workspace.current.clear();
    // Legacy live-slot lookup consumes encoded call offsets (return PC minus one).
    uint32_t queryOffset = safePoint && token.Version < 4 ? offset - 1 : offset;
    GcInfoDecoder decoder(token, DECODE_GC_LIFETIMES, queryOffset);
    decoder.EnumerateLiveSlots(&workspace.display, true,
        ActiveStackFrame | NoReportUntracked, ReportRoot, nullptr);
    RecordBytesRead(decoder);
    std::sort(workspace.current.begin(), workspace.current.end());

    for (uint32_t id : workspace.previous) {
        if (!std::binary_search(workspace.current.begin(), workspace.current.end(), id)) {
            workspace.events.push_back({offset, id, 0});
        }
    }
    for (uint32_t id : workspace.current) {
        if (!std::binary_search(workspace.previous.begin(), workspace.previous.end(), id)) {
            workspace.events.push_back({offset, id, 1});
        }
    }
    workspace.previous.swap(workspace.current);
}

ORACLE_EXPORT int ORACLE_FUNCTION(void* data, uint32_t version, uint32_t codeBound, Result* result) {
    GCInfoToken token(data);
    token.Version = version;
    GcInfoDecoder header(token);
    if (header.GetCodeLength() == 0 || header.GetCodeLength() > codeBound) {
        return 1;
    }

    workspace.roots.clear();
    workspace.ranges.clear();
    workspace.points.clear();
    workspace.events.clear();
    workspace.previous.clear();
    workspace.current.clear();
    workspace.untracked.clear();
    workspace.bytesRead = 0;
    workspace.reportFlags = 0;

    for (int reg = 0; reg < 16; ++reg) {
        workspace.registers[reg] = (uintptr_t)2 << 40;
    }
    workspace.display = {
        &workspace.registers[0], &workspace.registers[1], &workspace.registers[2],
        &workspace.registers[3], &workspace.registers[5], &workspace.registers[6],
        &workspace.registers[7], &workspace.registers[8], &workspace.registers[9],
        &workspace.registers[10], &workspace.registers[11], &workspace.registers[12],
        &workspace.registers[13], &workspace.registers[14], &workspace.registers[15],
        (uintptr_t)1 << 40
    };

    GcInfoDecoder ranges(token, DECODE_FOR_RANGES_CALLBACK);
    ranges.EnumerateInterruptibleRanges(ReportRange, nullptr);
    RecordBytesRead(ranges);

    GcInfoDecoder points(token);
    points.EnumerateSafePoints(ReportPoint, nullptr);
    RecordBytesRead(points);

    GcInfoDecoder untracked(token, DECODE_GC_LIFETIMES);
    workspace.reportFlags = GC_SLOT_UNTRACKED;
    untracked.EnumerateUntrackedSlots(&workspace.display, ActiveStackFrame, ReportRoot, nullptr);
    workspace.untracked.swap(workspace.current);
    workspace.reportFlags = 0;
    RecordBytesRead(untracked);
    uint32_t headerBytes = (uint32_t)untracked.GetNumBytesRead();

    uint64_t samples = 0;
    for (Range range : workspace.ranges) {
        if (range.start >= range.end || range.end > header.GetCodeLength()) {
            return 2;
        }
        for (uint32_t offset = range.start; offset < range.end; ++offset) {
            Sample(token, offset);
            ++samples;
        }
    }
    for (uint32_t offset : workspace.points) {
        if (offset > header.GetCodeLength()) {
            return 3;
        }
        Sample(token, offset, true);
        ++samples;
    }

    uint64_t capacity = workspace.roots.capacity() * sizeof(Root)
        + workspace.ranges.capacity() * sizeof(Range)
        + workspace.events.capacity() * sizeof(Event)
        + (workspace.points.capacity() + workspace.current.capacity()
            + workspace.previous.capacity() + workspace.untracked.capacity()) * sizeof(uint32_t);

    *result = {
        header.GetCodeLength(), header.GetSizeOfStackParameterArea(),
        header.GetGSCookieValidRangeStart(), header.GetGSCookieValidRangeEnd(),
        (int32_t)header.GetStackBaseRegister(), header.GetGSCookieStackSlot(),
        header.GetGenericsInstContextStackSlot(), header.GetReversePInvokeFrameStackSlot(),
        header.GetPSPSymStackSlot(),
        header.GetSizeOfEditAndContinuePreservedArea() == NO_SIZE_OF_EDIT_AND_CONTINUE_PRESERVED_AREA
            ? 0 : header.GetSizeOfEditAndContinuePreservedArea(),
        headerBytes, workspace.bytesRead, (uint32_t)workspace.roots.size(),
        (uint32_t)workspace.ranges.size(), (uint32_t)workspace.points.size(),
        (uint32_t)workspace.events.size(), (uint32_t)workspace.untracked.size(),
        version >= 4 ? -1 : (int32_t)header.GetReturnKind(),
        header.GetGenericsInstContextStackSlot() == NO_GENERICS_INST_CONTEXT ? 0U
            : header.HasMethodTableGenericsInstContext() ? 1U
            : header.HasMethodDescGenericsInstContext() ? 2U : 3U,
        header.HasStackBaseRegister() ? 1U : 0U,
        header.GetIsVarArg() ? 1U : 0U,
        header.WantsReportOnlyLeaf() ? 1U : 0U,
        header.GetSizeOfEditAndContinuePreservedArea() == NO_SIZE_OF_EDIT_AND_CONTINUE_PRESERVED_AREA ? 0U : 1U,
        samples, capacity, workspace.roots.data(), workspace.ranges.data(),
        workspace.points.data(), workspace.events.data(), workspace.untracked.data()
    };
    return 0;
}
