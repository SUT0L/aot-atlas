#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <stdatomic.h>
#include <unistd.h>
#include <pthread.h>

// Compile with the independently obtained ABI 187 header. Its declarations
// check every exported test-host signature against the actual C contract.
#define CAPACITY 4096

void BNLogString(size_t session, BNLogLevel level, const char* logger, size_t thread, const char* text) {
    if (level == ErrorLog)
        fprintf(stderr, "%s\n", text);
}

struct BNAnalysisCompletionEvent {
    void* context;
    void (*callback)(void* context);
    atomic_int references;
};

static pthread_mutex_t completionLock = PTHREAD_MUTEX_INITIALIZER;
static BNAnalysisCompletionEvent* pendingCompletions[CAPACITY];
static int pendingCompletionCount;
static atomic_int completionCount;
static atomic_int viewReferences;
static atomic_int fileReferences;
static atomic_int analysisUpdates;
static atomic_bool immediateCompletion;
static atomic_bool failCompletionRegistration;
static atomic_bool backgroundQueryBlocked;
static atomic_bool backgroundQueryEntered;
static atomic_int backgroundQueries;
static atomic_bool taskCancelled;
static atomic_bool blockingWaitEntered;
static atomic_bool blockingWaitReleased;
static pthread_mutex_t publicationLock = PTHREAD_MUTEX_INITIALIZER;
static BNBinaryDataNotification* publicationNotification;
static BNBinaryView* publicationView;
static atomic_bool delayedBarrier;
static atomic_int notificationCount;
static _Thread_local bool insideBarrier;

BNBasicBlock* BNGetFunctionBasicBlockAtAddress(BNFunction* function, BNArchitecture* architecture, uint64_t address) {
    assert(function && architecture);
    return (BNBasicBlock*)function;
}

void BNFreeBasicBlock(BNBasicBlock* block) {
    assert(block);
}
static uint8_t* rawBytes;
static size_t rawLength;
static int rawReads;
static int rawBuffers;
static int rawCallbackStage;
static void* rawCallbackContext;
static void (*rawCallback)(void* context);
static atomic_uintptr_t currentPeView = 1;
static atomic_bool analysisHold;

void ModelAnalysisHold(bool held) {
    analysisHold = held;
}

BNAnalysisState BNGetAnalysisState(BNBinaryView* view) {
    return analysisHold ? HoldState : IdleState;
}

char* BNTagTypeGetId(BNTagType* type) {
    char text[32];
    snprintf(text, sizeof(text), "tagtype-%lu", (unsigned long)(uintptr_t)type);
    return strdup(text);
}

char* BNTagTypeGetName(BNTagType* type) {
    return strdup(type == (BNTagType*)6 ? "another category" : "AOT Atlas test category");
}

void ModelCurrentPeView(BNBinaryView* view) {
    currentPeView = (uintptr_t)view;
}

struct BNDataBuffer {
    uint8_t* bytes;
    size_t length;
};

void ModelRawBytes(uint8_t* bytes, size_t length) {
    free(rawBytes);
    rawBytes = malloc(length);
    memcpy(rawBytes, bytes, length);
    rawLength = length;
}

void ModelRawCallback(int stage, void* context, void (*callback)(void* context)) {
    rawCallbackStage = stage;
    rawCallbackContext = context;
    rawCallback = callback;
}

int ModelRawReads(void) {
    return rawReads;
}

int ModelRawBuffers(void) {
    return rawBuffers;
}

char* BNGetViewType(BNBinaryView* view) {
    return strdup(view == (BNBinaryView*)3 ? "Raw" : "PE");
}

BNFileMetadata* BNGetFileForView(BNBinaryView* view) {
    ++fileReferences;
    return (BNFileMetadata*)5;
}

void BNFreeFileMetadata(BNFileMetadata* file) {
    assert(atomic_fetch_sub(&fileReferences, 1) > 0);
}

int ModelFileReferences(void) {
    return fileReferences;
}

BNBinaryView* BNGetFileViewOfType(BNFileMetadata* file, const char* type) {
    assert(!insideBarrier);
    BNBinaryView* view = strcmp(type, "Raw") == 0 ? (BNBinaryView*)3 : (BNBinaryView*)currentPeView;
    return view ? BNNewViewReference(view) : NULL;
}

BNBinaryView* BNGetParentView(BNBinaryView* view) {
    assert(view == (BNBinaryView*)1 || view == (BNBinaryView*)9);
    return BNNewViewReference((BNBinaryView*)3);
}

uint64_t BNGetViewLength(BNBinaryView* view) {
    return rawLength;
}

BNDataBuffer* BNReadViewBuffer(BNBinaryView* view, uint64_t offset, uint64_t length) {
    assert(view == (BNBinaryView*)3 && offset == 0 && length == rawLength);
    BNDataBuffer* buffer = malloc(sizeof(BNDataBuffer));
    buffer->length = length;
    buffer->bytes = malloc(length);
    memcpy(buffer->bytes, rawBytes, length);
    ++rawReads;
    ++rawBuffers;
    if (rawCallbackStage == 1)
        rawCallback(rawCallbackContext);
    return buffer;
}

size_t BNGetDataBufferLength(BNDataBuffer* buffer) {
    return buffer->length;
}

void* BNGetDataBufferContents(BNDataBuffer* buffer) {
    if (rawCallbackStage == 2)
        rawCallback(rawCallbackContext);
    return buffer->bytes;
}

void BNFreeDataBuffer(BNDataBuffer* buffer) {
    free(buffer->bytes);
    free(buffer);
    --rawBuffers;
}

void ModelDelayedBarrier(bool delayed) {
    delayedBarrier = delayed;
}

int ModelNotificationCount(void) {
    return notificationCount;
}

void ModelCompleteBarrier(void) {
    pthread_mutex_lock(&publicationLock);
    if (publicationNotification) {
        insideBarrier = true;
        publicationNotification->notificationBarrier(publicationNotification->context, publicationView);
        insideBarrier = false;
    }
    pthread_mutex_unlock(&publicationLock);
}

void BNRegisterDataNotification(BNBinaryView* view, BNBinaryDataNotification* notification) {
    assert(notification->notificationBarrier);
    assert(sizeof(*notification) == 56 * sizeof(void*));
    pthread_mutex_lock(&publicationLock);
    assert(!publicationNotification);
    publicationNotification = notification;
    publicationView = view;
    ++notificationCount;
    pthread_mutex_unlock(&publicationLock);

    if (!delayedBarrier)
        ModelCompleteBarrier();
}

void ModelRepeatBarrier(void) {
    assert(insideBarrier && publicationNotification);
    publicationNotification->notificationBarrier(publicationNotification->context, publicationView);
}

void BNExecuteOnMainThreadAndWait(void* context, void (*callback)(void* context)) {
    assert(!insideBarrier);
    callback(context);
}

void BNUnregisterDataNotification(BNBinaryView* view, BNBinaryDataNotification* notification) {
    pthread_mutex_lock(&publicationLock);
    assert(publicationNotification == notification);
    publicationNotification = NULL;
    publicationView = NULL;
    --notificationCount;
    pthread_mutex_unlock(&publicationLock);
}

void ModelReleaseBlockingWait(void) {
    blockingWaitReleased = true;
}

bool ModelBlockingWaitEntered(void) {
    return blockingWaitEntered;
}

void BNUpdateAnalysisAndWait(BNBinaryView* view) {
    blockingWaitEntered = true;

    while (!blockingWaitReleased)
        usleep(1000);
}

void ModelImmediateCompletion(bool value) {
    immediateCompletion = value;
}

void ModelCancelTask(bool value) {
    taskCancelled = value;
}

void ModelFailCompletionRegistration(bool value) {
    failCompletionRegistration = value;
}

void ModelBlockBackgroundQuery(bool value) {
    backgroundQueryBlocked = value;
}

bool ModelBackgroundQueryEntered(void) {
    return backgroundQueryEntered;
}

int ModelBackgroundQueries(void) {
    return backgroundQueries;
}

int ModelWaitCount(int kind) {
    switch (kind) {
        case 0:
            return completionCount;
        case 1:
            return viewReferences;
        case 2:
            return analysisUpdates;
        default: {
            pthread_mutex_lock(&completionLock);
            int count = pendingCompletionCount;
            pthread_mutex_unlock(&completionLock);
            return count;
        }
    }
}

static void ReleaseCompletion(BNAnalysisCompletionEvent* event) {
    if (atomic_fetch_sub(&event->references, 1) == 1)
        free(event);
}

void ModelCompleteWait(void) {
    pthread_mutex_lock(&completionLock);
    assert(pendingCompletionCount > 0);
    BNAnalysisCompletionEvent* event = pendingCompletions[0];
    memmove(pendingCompletions, pendingCompletions + 1, --pendingCompletionCount * sizeof(*pendingCompletions));
    pthread_mutex_unlock(&completionLock);
    event->callback(event->context);
    ReleaseCompletion(event);
}

BNBinaryView* BNNewViewReference(BNBinaryView* view) {
    ++viewReferences;
    return view;
}

void BNFreeBinaryView(BNBinaryView* view) {
    --viewReferences;
}

void BNUpdateAnalysis(BNBinaryView* view) {
    ++analysisUpdates;
}

BNAnalysisCompletionEvent* BNAddAnalysisCompletionEvent(BNBinaryView* view, void* context, void (*callback)(void* context)) {
    if (failCompletionRegistration)
        return NULL;

    BNAnalysisCompletionEvent* event = malloc(sizeof(BNAnalysisCompletionEvent));
    // One caller reference and one host registration reference. Releasing the
    // caller reference leaves the callback registered until host delivery.
    *event = (BNAnalysisCompletionEvent){context, callback, 2};

    if (immediateCompletion) {
        callback(context);
        ReleaseCompletion(event);
    } else {
        pthread_mutex_lock(&completionLock);
        assert(pendingCompletionCount < CAPACITY);
        pendingCompletions[pendingCompletionCount++] = event;
        pthread_mutex_unlock(&completionLock);
    }

    ++completionCount;
    return event;
}

void BNFreeAnalysisCompletionEvent(BNAnalysisCompletionEvent* event) {
    --completionCount;
    ReleaseCompletion(event);
}

bool BNIsBackgroundTaskCancelled(BNBackgroundTask* task) {
    ++backgroundQueries;
    if (backgroundQueryBlocked) {
        backgroundQueryEntered = true;
        while (backgroundQueryBlocked)
            usleep(1000);
    }
    return taskCancelled;
}

struct BNType {
    uint64_t shape;
};

// An independently described graph reaches incomplete declarations through each
// native aggregate path. The "Complete" reference already has a full definition.
#define GRAPH_SHAPE UINT64_C(0x1000000000000000)
static BNType graphTypes[12];
static int graphVisits[12];
struct BNNamedTypeReference {
    int node;
};
static BNNamedTypeReference graphReferences[] = {{2}, {6}, {7}, {9}, {10}, {11}};

BNType* ModelForwardType(void) {
    for (int i = 0; i < 12; ++i)
        graphTypes[i].shape = GRAPH_SHAPE + i;
    memset(graphVisits, 0, sizeof(graphVisits));
    return &graphTypes[0];
}

int ModelGraphVisits(int node) {
    return graphVisits[node];
}

static int graphNode(BNType* type) {
    return type && type->shape >= GRAPH_SHAPE && type->shape < GRAPH_SHAPE + 12
        ? (int)(type->shape - GRAPH_SHAPE) : -1;
}

static BNQualifiedName graphName(int node) {
    static char* opaque[] = {"Model", "Opaque"};
    static char* base[] = {"Model", "Base"};
    static char* complete[] = {"Model", "Complete"};
    static char* array[] = {"Model", "ArrayElement"};
    static char* returned[] = {"Model", "Returned"};
    static char* fragment[] = {"Model", "Fragment"};
    char** parts = node == 2 ? opaque : node == 6 ? base : node == 7 ? complete
        : node == 9 ? array : node == 10 ? returned : fragment;
    return (BNQualifiedName){parts, "::", 2};
}

static bool snapshotUnsigned;
static int libraryLoads;
static int libraryExports;
static int lastLibraryEntries;

int ModelLibraryExports(void) {
    return libraryExports;
}

int ModelLastLibraryEntries(void) {
    return lastLibraryEntries;
}

void ModelSnapshotUnsigned(bool value) {
    snapshotUnsigned = value;
}

int ModelLibraryLoads(void) {
    return libraryLoads;
}

struct BNSymbol {
    uint64_t address;
    char* shortName;
    char* fullName;
    char* rawName;
    BNSymbolType kind;
    bool automatic;
    BNSymbolBinding binding;
    uint64_t ordinal;
    BNNameSpace nameSpace;
};

struct BNFunction {
    uint64_t address;
    BNType* type;
    bool userType;
    bool comment;
    bool present;
};

struct BNMetadata {
    bool raw;
    size_t length;
    uint8_t* bytes;
};

struct BNTagType {
    int identity;
};

struct BNTag {
    char* identity;
    char* text;
    BNTagType* type;
    bool present;
};

struct BNTypeLibrary {
    BNType* types[CAPACITY];
    BNQualifiedName names[CAPACITY];
    int count;
};

typedef struct {
    char* id;
    BNQualifiedName name;
    BNType* type;
    bool automatic;
} NamedType;

typedef struct {
    char* key;
    BNMetadata* value;
} StoredMetadata;

typedef struct {
    uint64_t source;
    uint64_t target;
    bool present;
} Reference;

typedef struct {
    BNFunction* function;
    uint64_t address;
    BNQualifiedName name;
    uint64_t offset;
    size_t size;
    bool present;
} FieldReference;

static NamedType namedTypes[CAPACITY];
static int namedCount;
static BNSymbol* symbols[CAPACITY];
static int symbolCount;
static BNSymbol* pendingSymbols[CAPACITY];
static int pendingSymbolCount;
static bool bulkSymbols;
static BNDataVariable variables[CAPACITY];
static int variableCount;
static BNFunction functions[CAPACITY];
static int functionCount;
static Reference references[CAPACITY];
static int referenceCount;
static FieldReference fields[CAPACITY];
static int fieldCount;
static StoredMetadata metadata[CAPACITY];
static int metadataCount;
static BNTag* tags[CAPACITY];
static int tagCount;
static BNTagReference tagReferences[CAPACITY];
static int tagReferenceCount;
static uint64_t imageBase = 0x10000000;
static bool failWrite;
static bool loseReceipt;
static int lostReads;
static bool loseAbiReceipt;
static int lostFunctionReads;
static uint64_t lostFunctionAddress;
static bool loseTypeReceipt;
static const char* edgeSources[32];
static const char* edgeTargets[32];
static bool edgeActive[32];
static int edgeCount;
static bool raceAtVariableWrite;
static uint64_t raceAddress;
static BNType* raceType;
static pthread_t raceWriter;
static atomic_bool raceWriterAttempted;
static atomic_bool raceWriterFinished;

static void* changeVariable(void* context) {
    BNTypeWithConfidence confidence = {raceType, 255};
    raceWriterAttempted = true;
    BNDefineUserDataVariable((BNBinaryView*)1, raceAddress, &confidence);
    raceWriterFinished = true;
    return NULL;
}

void ModelRaceVariable(uint64_t address, BNType* type) {
    raceAddress = address;
    raceType = type;
    raceWriterAttempted = false;
    raceWriterFinished = false;
    raceAtVariableWrite = true;
}

void ModelJoinWriter(void) {
    pthread_join(raceWriter, NULL);
}

void ModelEdge(const char* source, const char* target, bool active) {
    for (int i = 0; i < edgeCount; ++i) {
        if (strcmp(edgeSources[i], source) == 0 && strcmp(edgeTargets[i], target) == 0) {
            edgeActive[i] = active;
            return;
        }
    }
    edgeSources[edgeCount] = strdup(source);
    edgeTargets[edgeCount] = strdup(target);
    edgeActive[edgeCount++] = active;
}

static BNQualifiedName copyName(const BNQualifiedName* name) {
    BNQualifiedName result = *name;
    result.name = calloc(name->nameCount, sizeof(char*));
    for (size_t i = 0; i < name->nameCount; ++i) {
        result.name[i] = strdup(name->name[i]);
    }
    result.join = strdup(name->join);
    return result;
}

static bool equalName(const BNQualifiedName* left, const BNQualifiedName* right) {
    if (left->nameCount != right->nameCount) {
        return false;
    }
    for (size_t i = 0; i < left->nameCount; ++i) {
        if (strcmp(left->name[i], right->name[i]) != 0) {
            return false;
        }
    }
    return true;
}

BNType* ModelType(uint64_t shape) {
    if (shape >= GRAPH_SHAPE && shape < GRAPH_SHAPE + 12)
        return &graphTypes[shape - GRAPH_SHAPE];
    BNType* type = malloc(sizeof(BNType));
    type->shape = shape;
    return type;
}

void ModelFailWrite(bool value) {
    failWrite = value;
}

void ModelLoseReceipt(void) {
    loseReceipt = true;
}

void ModelLoseAbiReceipt(void) {
    loseAbiReceipt = true;
}

void ModelLoseTypeReceipt(void) {
    loseTypeReceipt = true;
}

void ModelComment(uint64_t address) {
    for (int i = 0; i < functionCount; ++i) {
        if (functions[i].address == address) {
            functions[i].comment = true;
        }
    }
}

void ModelUserType(uint64_t address, BNType* type) {
    for (int i = 0; i < functionCount; ++i) {
        if (functions[i].address == address) {
            functions[i].type = type;
            functions[i].userType = true;
        }
    }
}

void ModelRebase(uint64_t next) {
    uint64_t delta = next - imageBase;
    for (int i = 0; i < symbolCount; ++i) {
        symbols[i]->address += delta;
    }
    for (int i = 0; i < variableCount; ++i) {
        variables[i].address += delta;
    }
    for (int i = 0; i < functionCount; ++i) {
        functions[i].address += delta;
    }
    for (int i = 0; i < referenceCount; ++i) {
        references[i].source += delta;
        references[i].target += delta;
    }
    for (int i = 0; i < fieldCount; ++i) {
        fields[i].address += delta;
    }
    for (int i = 0; i < tagReferenceCount; ++i) {
        tagReferences[i].addr += delta;
    }
    imageBase = next;
}

uint32_t BNGetCurrentCoreABIVersion(void) {
    return 187;
}

uint64_t BNGetImageBase(BNBinaryView* view) {
    return imageBase;
}

BNPlatform* BNGetDefaultPlatform(BNBinaryView* view) {
    return (BNPlatform*)2;
}

BNArchitecture* BNGetPlatformArchitecture(BNPlatform* platform) {
    return (BNArchitecture*)3;
}

void BNFreePlatform(BNPlatform* platform) {
}

void BNFreeType(BNType* type) {
}

BNType* BNNewTypeReference(BNType* type) {
    return type;
}

bool BNTypesEqual(BNType* left, BNType* right) {
    uint64_t mask = UINT64_C(0xff000000ffffffff);
    return (left->shape & mask) == (right->shape & mask);
}

BNTypeClass BNGetTypeClass(BNType* type) {
    int node = graphNode(type);
    if (node >= 0) {
        ++graphVisits[node];
        const BNTypeClass classes[] = {
            StructureTypeClass, PointerTypeClass, NamedTypeReferenceClass,
            ArrayTypeClass, FunctionTypeClass, FragmentTypeClass,
            NamedTypeReferenceClass, NamedTypeReferenceClass, StructureTypeClass,
            NamedTypeReferenceClass, NamedTypeReferenceClass, NamedTypeReferenceClass
        };
        return classes[node];
    }
    return type->shape >> 63 ? EnumerationTypeClass : IntegerTypeClass;
}

BNTypeWithConfidence BNGetChildType(BNType* type) {
    int node = graphNode(type);
    assert(node == 1 || node == 3 || node == 5);
    return (BNTypeWithConfidence){&graphTypes[node == 3 ? 9 : node == 5 ? 11 : 2], 255};
}

BNStructure* BNGetTypeStructure(BNType* type) {
    assert(graphNode(type) == 0 || graphNode(type) == 8);
    return (BNStructure*)type;
}

BNStructureMember* BNGetStructureMembers(BNStructure* structure, size_t* count) {
    int nodes[] = {1, 3, 4, 7, 1};
    *count = graphNode((BNType*)structure) == 0 ? 5 : 1;
    BNStructureMember* members = calloc(*count, sizeof(BNStructureMember));
    for (size_t i = 0; i < *count; ++i) {
        members[i].type = &graphTypes[nodes[i]];
        members[i].typeConfidence = 255;
        members[i].offset = i * 8;
    }
    return members;
}

void BNFreeStructureMemberList(BNStructureMember* members, size_t count) {
    free(members);
}

BNBaseStructure* BNGetBaseStructuresForStructure(BNStructure* structure, size_t* count) {
    *count = graphNode((BNType*)structure) == 0 ? 1 : 0;
    BNBaseStructure* bases = calloc(*count, sizeof(BNBaseStructure));
    if (*count)
        bases[0] = (BNBaseStructure){&graphReferences[1], 0, 8};
    return bases;
}

void BNFreeBaseStructureList(BNBaseStructure* bases, size_t count) {
    free(bases);
}

void BNFreeStructure(BNStructure* structure) {
}

BNType* BNCreateNamedTypeReference(BNNamedTypeReference* reference, size_t width, size_t alignment,
    BNBoolWithConfidence* cnst, BNBoolWithConfidence* vol) {
    return &graphTypes[reference->node];
}

BNNamedTypeReference* BNGetTypeNamedTypeReference(BNType* type) {
    int node = graphNode(type);
    for (int i = 0; i < 6; ++i)
        if (graphReferences[i].node == node)
            return &graphReferences[i];
    assert(false);
    return NULL;
}

BNQualifiedName BNGetTypeReferenceName(BNNamedTypeReference* reference) {
    BNQualifiedName name = graphName(reference->node);
    return copyName(&name);
}

void BNFreeNamedTypeReference(BNNamedTypeReference* reference) {
}

uint64_t BNGetTypeWidth(BNType* type) {
    return (type->shape >> 56) & 15;
}

BNBoolWithConfidence BNIsTypeSigned(BNType* type) {
    return (BNBoolWithConfidence){(type->shape >> 62) & 1, 255};
}

BNTypeBuilder* BNCreateTypeBuilderFromType(BNType* type) {
    return (BNTypeBuilder*)ModelType(type->shape);
}

void BNTypeBuilderSetSigned(BNTypeBuilder* builder, BNBoolWithConfidence* sign) {
    BNType* type = (BNType*)builder;
    type->shape = (type->shape & ~(UINT64_C(1) << 62)) | ((uint64_t)sign->value << 62);
}

BNType* BNFinalizeTypeBuilder(BNTypeBuilder* builder) {
    return ModelType(((BNType*)builder)->shape);
}

void BNFreeTypeBuilder(BNTypeBuilder* builder) {
    free(builder);
}

void BNFreeString(char* text) {
    free(text);
}

char* BNAllocString(const char* text) {
    return strdup(text);
}

char** BNAllocStringList(const char** text, size_t count) {
    char** result = calloc(count, sizeof(char*));
    for (size_t i = 0; i < count; ++i) {
        result[i] = strdup(text[i]);
    }
    return result;
}

void BNFreeQualifiedName(BNQualifiedName* name) {
    for (size_t i = 0; i < name->nameCount; ++i) {
        free(name->name[i]);
    }
    free(name->name);
    free(name->join);
}

static NamedType* named(const char* id) {
    for (int i = 0; i < namedCount; ++i) {
        if (namedTypes[i].id && strcmp(namedTypes[i].id, id) == 0) {
            return &namedTypes[i];
        }
    }
    return NULL;
}

BNType* BNGetAnalysisTypeById(BNBinaryView* view, const char* id) {
    NamedType* entry = named(id);
    return entry ? entry->type : NULL;
}

BNQualifiedName BNGetAnalysisTypeNameById(BNBinaryView* view, const char* id) {
    NamedType* entry = named(id);
    BNQualifiedName empty = {0};
    return entry ? copyName(&entry->name) : empty;
}

BNQualifiedName BNDefineAnalysisType(BNBinaryView* view, const char* id, BNQualifiedName* name, BNType* type) {
    NamedType* entry = named(id);
    if (!entry) {
        entry = &namedTypes[namedCount++];
        entry->id = strdup(id);
    }
    entry->name = copyName(name);
    entry->type = type;
    entry->automatic = true;
    if (loseTypeReceipt) {
        loseTypeReceipt = false;
        BNQualifiedName empty = {0};
        return empty;
    }
    return copyName(name);
}

void BNUndefineAnalysisType(BNBinaryView* view, const char* id) {
    NamedType* entry = named(id);
    if (entry) {
        entry->id = NULL;
    }
}

bool BNIsAnalysisTypeAutoDefined(BNBinaryView* view, BNQualifiedName* name) {
    for (int i = 0; i < namedCount; ++i) {
        if (namedTypes[i].id && equalName(&namedTypes[i].name, name)) {
            return namedTypes[i].automatic;
        }
    }
    return false;
}

BNQualifiedNameAndType* BNGetAnalysisTypeList(BNBinaryView* view, size_t* count) {
    BNQualifiedNameAndType* result = calloc(namedCount, sizeof(BNQualifiedNameAndType));
    *count = 0;
    for (int i = 0; i < namedCount; ++i) {
        if (namedTypes[i].id) {
            result[*count].name = copyName(&namedTypes[i].name);
            result[(*count)++].type = namedTypes[i].type;
        }
    }
    return result;
}

char* BNGetAnalysisTypeId(BNBinaryView* view, BNQualifiedName* name) {
    for (int i = 0; i < namedCount; ++i) {
        if (namedTypes[i].id && equalName(&namedTypes[i].name, name)) {
            return strdup(namedTypes[i].id);
        }
    }
    return strdup("");
}

void BNFreeTypeAndNameList(BNQualifiedNameAndType* types, size_t count) {
    for (size_t i = 0; i < count; ++i) {
        BNFreeQualifiedName(&types[i].name);
    }
    free(types);
}

BNSymbol* BNCreateSymbol(BNSymbolType kind, const char* shortName, const char* fullName,
    const char* rawName, uint64_t address, BNSymbolBinding binding, const BNNameSpace* nameSpace, uint64_t ordinal) {
    BNSymbol* symbol = calloc(1, sizeof(BNSymbol));
    symbol->address = address;
    symbol->kind = kind;
    symbol->shortName = strdup(shortName);
    symbol->fullName = strdup(fullName);
    symbol->rawName = strdup(rawName);
    symbol->binding = binding;
    symbol->ordinal = ordinal;
    if (nameSpace) {
        symbol->nameSpace = *nameSpace;
        symbol->nameSpace.name = BNAllocStringList((const char**)nameSpace->name, nameSpace->nameCount);
        symbol->nameSpace.join = strdup(nameSpace->join);
    }
    return symbol;
}

BNSymbol* BNGetSymbolByAddress(BNBinaryView* view, uint64_t address, const BNNameSpace* nameSpace) {
    for (int i = 0; i < symbolCount; ++i) {
        if (symbols[i]->address == address) {
            return symbols[i];
        }
    }
    return NULL;
}

void BNDefineUserSymbol(BNBinaryView* view, BNSymbol* symbol) {
    if (bulkSymbols) {
        for (int i = 0; i < pendingSymbolCount; ++i) {
            if (pendingSymbols[i]->address == symbol->address) {
                pendingSymbols[i] = symbol;
                return;
            }
        }
        pendingSymbols[pendingSymbolCount++] = symbol;
        return;
    }

    for (int i = 0; i < symbolCount; ++i) {
        if (symbols[i]->address == symbol->address) {
            symbols[i] = symbol;
            return;
        }
    }
    symbols[symbolCount++] = symbol;
}

BNSymbol** BNGetSymbols(BNBinaryView* view, size_t* count, const BNNameSpace* nameSpace) {
    BNSymbol** result = calloc(symbolCount, sizeof(BNSymbol*));
    memcpy(result, symbols, symbolCount * sizeof(BNSymbol*));
    *count = symbolCount;
    return result;
}

void BNFreeSymbolList(BNSymbol** list, size_t count) {
    free(list);
}

void BNBeginBulkModifySymbols(BNBinaryView* view) {
    assert(!bulkSymbols);
    bulkSymbols = true;
}

void BNEndBulkModifySymbols(BNBinaryView* view) {
    bulkSymbols = false;
    for (int i = 0; i < pendingSymbolCount; ++i) {
        BNDefineUserSymbol(view, pendingSymbols[i]);
    }
    pendingSymbolCount = 0;
}

void BNUndefineUserSymbol(BNBinaryView* view, BNSymbol* symbol) {
    for (int i = 0; i < symbolCount; ++i) {
        if (symbols[i] == symbol) {
            symbols[i] = symbols[--symbolCount];
            return;
        }
    }
}

char* BNGetSymbolRawName(BNSymbol* symbol) {
    return strdup(symbol->rawName);
}

char* BNGetSymbolFullName(BNSymbol* symbol) {
    return strdup(symbol->fullName);
}

char* BNGetSymbolShortName(BNSymbol* symbol) {
    return strdup(symbol->shortName);
}

uint64_t BNGetSymbolAddress(BNSymbol* symbol) {
    return symbol->address;
}

BNSymbolType BNGetSymbolType(BNSymbol* symbol) {
    return symbol->kind;
}

bool BNIsSymbolAutoDefined(BNSymbol* symbol) {
    return symbol->automatic;
}

void BNFreeSymbol(BNSymbol* symbol) {
}

BNSymbolBinding BNGetSymbolBinding(BNSymbol* symbol) {
    return symbol->binding;
}

uint64_t BNGetSymbolOrdinal(BNSymbol* symbol) {
    return symbol->ordinal;
}

BNNameSpace BNGetSymbolNameSpace(BNSymbol* symbol) {
    BNNameSpace name = symbol->nameSpace;
    name.name = BNAllocStringList((const char**)name.name, name.nameCount);
    name.join = strdup(name.join ? name.join : "::");
    return name;
}

void BNFreeNameSpace(BNNameSpace* name) {
    for (size_t i = 0; i < name->nameCount; ++i) {
        free(name->name[i]);
    }
    free(name->name);
    free(name->join);
}

BNReturnValue BNGetTypeReturnValue(BNType* type) {
    BNReturnValue result = {0};
    result.type = graphNode(type) == 4 ? &graphTypes[10] : ModelType((uint32_t)type->shape);
    result.typeConfidence = 255 - (uint8_t)(type->shape >> 32);
    result.defaultLocation = true;
    return result;
}

BNFunctionParameter* BNGetTypeParameters(BNType* type, size_t* count) {
    BNFunctionParameter* result = calloc(1, sizeof(BNFunctionParameter));
    if (graphNode(type) == 4)
        result->type = &graphTypes[5];
    result->typeConfidence = 255;
    result->locationSource = CustomLocationSource;
    result->location.count = 1;
    result->location.components = calloc(1, sizeof(BNValueLocationComponent));
    result->location.components[0].variable.storage = 23 + (int64_t)(type->shape >> 40);
    *count = 1;
    return result;
}

void BNFreeTypeParameterList(BNFunctionParameter* parameters, size_t count) {
    for (size_t i = 0; i < count; ++i) {
        free(parameters[i].location.components);
    }
    free(parameters);
}

void BNFreeValueLocation(BNValueLocation* location) {
    free(location->components);
}
BNCallingConventionWithConfidence BNGetTypeCallingConvention(BNType* type) {
    BNCallingConventionWithConfidence result = {NULL, 255};
    return result;
}

BNOffsetWithConfidence BNGetTypeStackAdjustment(BNType* type) {
    BNOffsetWithConfidence result = {0, 255};
    return result;
}

BNBoolWithConfidence BNTypeHasVariableArguments(BNType* type) {
    BNBoolWithConfidence result = {false, 255};
    return result;
}

BNBoolWithConfidence BNFunctionTypeCanReturn(BNType* type) {
    BNBoolWithConfidence result = {true, 255};
    return result;
}

BNBoolWithConfidence BNIsTypePure(BNType* type) {
    BNBoolWithConfidence result = {false, 255};
    return result;
}

void BNFreeCallingConvention(BNCallingConvention* convention) {
}

bool BNGetDataVariableAtAddress(BNBinaryView* view, uint64_t address, BNDataVariable* result) {
    for (int i = 0; i < variableCount; ++i) {
        if (variables[i].address == address) {
            *result = variables[i];
            return true;
        }
    }
    return false;
}

void BNDefineUserDataVariable(BNBinaryView* view, uint64_t address, BNTypeWithConfidence* type) {
    if (raceAtVariableWrite && address == raceAddress) {
        raceAtVariableWrite = false;
        assert(pthread_create(&raceWriter, NULL, changeVariable, NULL) == 0);

        while (!raceWriterAttempted)
            usleep(100);

        if (!insideBarrier) {
            while (!raceWriterFinished)
                usleep(100);
        }
    }

    if (!insideBarrier)
        pthread_mutex_lock(&publicationLock);

    BNDataVariable variable = {0};
    variable.address = address;
    variable.type = type->type;
    variable.typeConfidence = type->confidence;
    for (int i = 0; i < variableCount; ++i) {
        if (variables[i].address == address) {
            variables[i] = variable;
            if (!insideBarrier)
                pthread_mutex_unlock(&publicationLock);
            return;
        }
    }
    variables[variableCount++] = variable;

    if (!insideBarrier)
        pthread_mutex_unlock(&publicationLock);
}

void BNUndefineUserDataVariable(BNBinaryView* view, uint64_t address) {
    for (int i = 0; i < variableCount; ++i) {
        if (variables[i].address == address) {
            variables[i] = variables[--variableCount];
            return;
        }
    }
}

void BNFreeDataVariable(BNDataVariable* variable) {
}

uint64_t* BNGetDataReferencesFrom(BNBinaryView* view, uint64_t address, size_t* count) {
    uint64_t* result = calloc(referenceCount, sizeof(uint64_t));
    *count = 0;
    for (int i = 0; i < referenceCount; ++i) {
        if (references[i].present && references[i].source == address) {
            result[(*count)++] = references[i].target;
        }
    }
    return result;
}

void BNAddUserDataReference(BNBinaryView* view, uint64_t source, uint64_t target) {
    for (int i = 0; i < referenceCount; ++i) {
        if (references[i].source == source && references[i].target == target) {
            references[i].present = true;
            return;
        }
    }
    references[referenceCount++] = (Reference){source, target, true};
}

void BNRemoveUserDataReference(BNBinaryView* view, uint64_t source, uint64_t target) {
    for (int i = 0; i < referenceCount; ++i) {
        if (references[i].source == source && references[i].target == target) {
            references[i].present = false;
        }
    }
}

void BNFreeDataReferences(uint64_t* references) {
    free(references);
}

BNFunction* BNGetAnalysisFunction(BNBinaryView* view, BNPlatform* platform, uint64_t address) {
    if (lostFunctionReads && address == lostFunctionAddress) {
        --lostFunctionReads;
        return NULL;
    }
    for (int i = 0; i < functionCount; ++i) {
        if (functions[i].present && functions[i].address == address) {
            return &functions[i];
        }
    }
    return NULL;
}

BNFunction* BNAddFunctionForAnalysis(BNBinaryView* view, BNPlatform* platform, uint64_t address,
    bool automatic, BNType* type) {
    BNFunction* function = BNGetAnalysisFunction(view, platform, address);
    if (!function) {
        function = &functions[functionCount++];
        *function = (BNFunction){address, type ? type : ModelType(0), false, false, true};
    }
    return function;
}

void BNRemoveAnalysisFunction(BNBinaryView* view, BNFunction* function, bool updateReferences) {
    function->present = false;
}

BNType* BNGetFunctionType(BNFunction* function) {
    return function->type;
}

uint64_t BNGetFunctionStart(BNFunction* function) {
    return function->address;
}

bool BNFunctionHasUserType(BNFunction* function) {
    return function->userType;
}
void BNApplyAutoDiscoveredFunctionType(BNFunction* function, BNType* type) {
    function->type = type;
    if (loseAbiReceipt) {
        loseAbiReceipt = false;
        lostFunctionAddress = function->address;
        lostFunctionReads = 1;
    }
}
void BNSetFunctionAutoType(BNFunction* function, BNType* type) {
    function->type = type;
}

void BNFreeFunction(BNFunction* function) {
}

bool BNFunctionHasUserAnnotations(BNFunction* function) {
    if (function->userType || function->comment || BNGetSymbolByAddress(NULL, function->address, NULL)) {
        return true;
    }
    for (int i = 0; i < tagReferenceCount; ++i) {
        if (tagReferences[i].func == function && tagReferences[i].tag) {
            return true;
        }
    }
    return false;
}

BNMetadata* BNCreateMetadataRawData(const uint8_t* bytes, size_t length) {
    BNMetadata* value = malloc(sizeof(BNMetadata));
    value->raw = true;
    value->length = length;
    value->bytes = malloc(length);
    memcpy(value->bytes, bytes, length);
    return value;
}

bool BNMetadataIsRaw(BNMetadata* value) {
    return value->raw;
}

void ModelNonRawMetadata(const char* key) {
    BNMetadata* value = BNBinaryViewQueryMetadata((BNBinaryView*)1, key);
    assert(value);
    value->raw = false;
}
uint8_t* BNMetadataGetRaw(BNMetadata* value, size_t* length) {
    *length = value->length;
    uint8_t* bytes = malloc(*length);
    memcpy(bytes, value->bytes, *length);
    return bytes;
}

void BNFreeMetadataRaw(uint8_t* bytes) {
    free(bytes);
}

void BNFreeMetadata(BNMetadata* metadata) {
}

BNMetadata* BNBinaryViewQueryMetadata(BNBinaryView* view, const char* key) {
    if (lostReads && strcmp(key, "aot-atlas:owned-annotations") == 0) {
        --lostReads;
        return NULL;
    }
    for (int i = 0; i < metadataCount; ++i) {
        if (metadata[i].key && strcmp(metadata[i].key, key) == 0) {
            return metadata[i].value;
        }
    }
    return NULL;
}

void BNBinaryViewStoreMetadata(BNBinaryView* view, const char* key, BNMetadata* value, BNMetadataStoreFlag flags) {
    if (loseReceipt && strcmp(key, "aot-atlas:owned-annotations") == 0) {
        loseReceipt = false;
        lostReads = 1;
    }
    for (int i = 0; i < metadataCount; ++i) {
        if (metadata[i].key && strcmp(metadata[i].key, key) == 0) {
            metadata[i].value = value;
            return;
        }
    }
    metadata[metadataCount++] = (StoredMetadata){strdup(key), value};
}

void BNBinaryViewRemoveMetadata(BNBinaryView* view, const char* key) {
    for (int i = 0; i < metadataCount; ++i) {
        if (metadata[i].key && strcmp(metadata[i].key, key) == 0) {
            metadata[i].key = NULL;
        }
    }
}

BNTypeLibrary* BNNewTypeLibrary(BNArchitecture* architecture, const char* name) {
    return calloc(1, sizeof(BNTypeLibrary));
}

void BNAddTypeLibraryNamedType(BNTypeLibrary* library, BNQualifiedName* name, BNType* type) {
    int index = 0;
    while (index < library->count && !equalName(&library->names[index], name))
        ++index;
    assert(index < CAPACITY);
    if (index == library->count) {
        library->names[index] = copyName(name);
        ++library->count;
    }
    library->types[index] = type;
}

void BNBinaryViewExportTypeToTypeLibrary(BNBinaryView* view, BNTypeLibrary* library, BNQualifiedName* name, BNType* type) {
    ++libraryExports;
    BNAddTypeLibraryNamedType(library, name, type);
    if (graphNode(type) >= 0) {
        BNQualifiedName complete = graphName(7);
        BNAddTypeLibraryNamedType(library, &complete, &graphTypes[8]);
    }
}

BNQualifiedNameAndType* BNGetTypeLibraryNamedTypes(BNTypeLibrary* library, size_t* count) {
    *count = library->count;
    BNQualifiedNameAndType* result = calloc(*count, sizeof(BNQualifiedNameAndType));
    for (size_t i = 0; i < *count; ++i) {
        result[i].name = copyName(&library->names[i]);
        result[i].type = library->types[i];
    }
    return result;
}

BNType* BNGetTypeLibraryNamedType(BNTypeLibrary* library, BNQualifiedName* name) {
    for (int i = 0; i < library->count; ++i)
        if (equalName(&library->names[i], name))
            return library->types[i];
    return NULL;
}

bool BNFinalizeTypeLibrary(BNTypeLibrary* library) {
    bool graph = false;
    for (int i = 0; i < library->count; ++i)
        graph |= graphNode(library->types[i]) >= 0;
    if (graph) {
        for (int i = 0; i < 6; ++i) {
            BNQualifiedName name = graphName(graphReferences[i].node);
            BNType* stored = BNGetTypeLibraryNamedType(library, &name);
            if (stored != &graphTypes[i == 2 ? 8 : graphReferences[i].node])
                return false;
        }
    }
    return true;
}

static void writeText(FILE* file, const char* text) {
    uint32_t length = (uint32_t)strlen(text);
    fwrite(&length, sizeof(length), 1, file);
    fwrite(text, 1, length, file);
}

static char* readText(FILE* file) {
    uint32_t length;
    assert(fread(&length, sizeof(length), 1, file) == 1 && length < 4096);
    char* text = calloc(length + 1, 1);
    assert(fread(text, 1, length, file) == length);
    return text;
}

bool BNWriteTypeLibraryToFile(BNTypeLibrary* library, const char* path) {
    lastLibraryEntries = library->count;
    if (failWrite) {
        return false;
    }
    FILE* file = fopen(path, "wb");
    assert(file);
    fwrite(&library->count, sizeof(int), 1, file);
    for (int i = 0; i < library->count; ++i) {
        fwrite(&library->types[i]->shape, sizeof(uint64_t), 1, file);
        uint32_t count = (uint32_t)library->names[i].nameCount;
        fwrite(&count, sizeof(count), 1, file);
        writeText(file, library->names[i].join);
        for (uint32_t j = 0; j < count; ++j)
            writeText(file, library->names[i].name[j]);
    }
    fclose(file);
    return true;
}

BNTypeLibrary* BNLoadTypeLibraryFromFile(const char* path) {
    ++libraryLoads;
    FILE* file = fopen(path, "rb");
    if (!file) {
        return NULL;
    }
    BNTypeLibrary* library = calloc(1, sizeof(BNTypeLibrary));
    assert(fread(&library->count, sizeof(int), 1, file) == 1);
    assert(library->count < CAPACITY);
    for (int i = 0; i < library->count; ++i) {
        uint64_t shape;
        assert(fread(&shape, sizeof(uint64_t), 1, file) == 1);
        library->types[i] = ModelType(snapshotUnsigned ? shape & ~(UINT64_C(1) << 62) : shape);
        uint32_t count;
        assert(fread(&count, sizeof(count), 1, file) == 1 && count < CAPACITY);
        library->names[i].nameCount = count;
        library->names[i].name = calloc(count, sizeof(char*));
        library->names[i].join = readText(file);
        for (uint32_t j = 0; j < count; ++j)
            library->names[i].name[j] = readText(file);
    }
    fclose(file);
    return library;
}

void BNFreeTypeLibrary(BNTypeLibrary* library) {
    for (int i = 0; i < library->count; ++i)
        BNFreeQualifiedName(&library->names[i]);
    free(library);
}

BNTag* BNCreateTag(BNTagType* type, const char* text) {
    BNTag* tag = calloc(1, sizeof(BNTag));
    tag->text = strdup(text);
    tag->type = type;
    return tag;
}

void BNAddTag(BNBinaryView* view, BNTag* tag, bool user) {
    char identity[32];
    snprintf(identity, sizeof(identity), "tag-%d", tagCount);
    tag->identity = strdup(identity);
    tag->present = true;
    tags[tagCount++] = tag;
}

char* BNTagGetId(BNTag* tag) {
    return strdup(tag->identity);
}

char* BNTagGetData(BNTag* tag) {
    return strdup(tag->text);
}

BNTagType* BNTagGetType(BNTag* tag) {
    return tag->type;
}

void BNTagSetData(BNTag* tag, const char* text) {
    tag->text = strdup(text);
}

void BNFreeTag(BNTag* tag) {
}

BNTag* BNNewTagReference(BNTag* tag) {
    return tag;
}

void BNFreeTagType(BNTagType* type) {
}

BNTag* BNGetTag(BNBinaryView* view, const char* identity) {
    for (int i = 0; i < tagCount; ++i) {
        if (tags[i]->present && strcmp(tags[i]->identity, identity) == 0) {
            return tags[i];
        }
    }
    return NULL;
}

void BNRemoveTag(BNBinaryView* view, BNTag* tag, bool user) {
    tag->present = false;
}

void BNAddUserDataTag(BNBinaryView* view, uint64_t address, BNTag* tag) {
    tagReferences[tagReferenceCount++] = (BNTagReference){DataTagReference, false, tag, NULL, NULL, address};
}

void BNAddUserFunctionTag(BNFunction* function, BNTag* tag) {
    tagReferences[tagReferenceCount++] = (BNTagReference){FunctionTagReference, false, tag, NULL, function, 0};
}

BNTag** BNGetUserDataTagsOfType(BNBinaryView* view, uint64_t address, BNTagType* type, size_t* count) {
    BNTag** result = calloc(tagReferenceCount, sizeof(BNTag*));
    *count = 0;
    for (int i = 0; i < tagReferenceCount; ++i) {
        BNTagReference* ref = &tagReferences[i];
        if (ref->tag && !ref->func && ref->addr == address && ref->tag->type == type) {
            result[(*count)++] = ref->tag;
        }
    }
    return result;
}

BNTag** BNGetUserFunctionTagsOfType(BNFunction* function, BNTagType* type, size_t* count) {
    BNTag** result = calloc(tagReferenceCount, sizeof(BNTag*));
    *count = 0;
    for (int i = 0; i < tagReferenceCount; ++i) {
        BNTagReference* ref = &tagReferences[i];
        if (ref->tag && ref->func == function && ref->tag->type == type) {
            result[(*count)++] = ref->tag;
        }
    }
    return result;
}

void BNRemoveUserDataTag(BNBinaryView* view, uint64_t address, BNTag* tag) {
    for (int i = 0; i < tagReferenceCount; ++i) {
        BNTagReference* ref = &tagReferences[i];
        if (ref->tag == tag && !ref->func && ref->addr == address) {
            ref->tag = NULL;
        }
    }
}

void BNRemoveUserFunctionTag(BNFunction* function, BNTag* tag) {
    for (int i = 0; i < tagReferenceCount; ++i) {
        BNTagReference* ref = &tagReferences[i];
        if (ref->tag == tag && ref->func == function) {
            ref->tag = NULL;
        }
    }
}

void BNFreeTagList(BNTag** tags, size_t count) {
    free(tags);
}

BNTagReference* BNGetAllTagReferences(BNBinaryView* view, size_t* count) {
    BNTagReference* result = calloc(tagReferenceCount, sizeof(BNTagReference));
    *count = 0;
    for (int i = 0; i < tagReferenceCount; ++i) {
        if (tagReferences[i].tag) {
            result[(*count)++] = tagReferences[i];
        }
    }
    return result;
}

void BNFreeTagReferences(BNTagReference* references, size_t count) {
    free(references);
}

void BNAddUserTypeFieldReference(BNFunction* function, BNArchitecture* architecture, uint64_t address,
    BNQualifiedName* name, uint64_t offset, size_t size) {
    for (int i = 0; i < fieldCount; ++i) {
        FieldReference* ref = &fields[i];
        if (ref->present && ref->function == function && ref->address == address && ref->offset == offset
            && ref->size == size && equalName(&ref->name, name)) {
            return;
        }
    }
    fields[fieldCount++] = (FieldReference){function, address, copyName(name), offset, size, true};
}

void BNRemoveUserTypeFieldReference(BNFunction* function, BNArchitecture* architecture, uint64_t address,
    BNQualifiedName* name, uint64_t offset, size_t size) {
    for (int i = 0; i < fieldCount; ++i) {
        FieldReference* ref = &fields[i];
        if (ref->function == function && ref->address == address && ref->offset == offset && ref->size == size
            && equalName(&ref->name, name)) {
            ref->present = false;
        }
    }
}

BNTypeFieldReference* BNGetCodeReferencesForTypeField(BNBinaryView* view, BNQualifiedName* name,
    uint64_t offset, size_t* count, bool limit, size_t maximum) {
    BNTypeFieldReference* result = calloc(fieldCount, sizeof(BNTypeFieldReference));
    *count = 0;
    for (int i = 0; i < fieldCount; ++i) {
        FieldReference* ref = &fields[i];
        if (ref->present && ref->offset == offset && equalName(&ref->name, name)) {
            result[(*count)++] = (BNTypeFieldReference){ref->function, (BNArchitecture*)3, ref->address, ref->size, {0}};
        }
    }
    return result;
}

void BNFreeTypeFieldReferences(BNTypeFieldReference* references, size_t count) {
    free(references);
}

BNReferenceSource* BNGetCodeReferencesForType(BNBinaryView* view, BNQualifiedName* name,
    size_t* count, bool limit, size_t maximum) {
    *count = 0;
    return NULL;
}

uint64_t* BNGetDataReferencesForType(BNBinaryView* view, BNQualifiedName* name,
    size_t* count, bool limit, size_t maximum) {
    *count = 0;
    return NULL;
}

BNTypeReferenceSource* BNGetTypeReferencesForType(BNBinaryView* view, BNQualifiedName* name,
    size_t* count, bool limit, size_t maximum) {
    BNTypeReferenceSource* result = calloc(edgeCount, sizeof(BNTypeReferenceSource));
    *count = 0;
    for (int i = 0; i < edgeCount; ++i) {
        NamedType* target = named(edgeTargets[i]);
        if (!edgeActive[i] || !target || !equalName(&target->name, name)) {
            continue;
        }
        NamedType* source = named(edgeSources[i]);
        char* part = "AnalystType";
        BNQualifiedName external = {&part, "::", 1};
        result[*count].name = copyName(source ? &source->name : &external);
        result[(*count)++].offset = 0;
    }
    return result;
}

void BNFreeCodeReferences(BNReferenceSource* references, size_t count) {
    free(references);
}

void BNFreeTypeReferences(BNTypeReferenceSource* references, size_t count) {
    for (size_t i = 0; i < count; ++i) {
        BNFreeQualifiedName(&references[i].name);
    }
    free(references);
}

int ModelCount(int kind) {
    int count = 0;
    if (kind == 0) {
        for (int i = 0; i < namedCount; ++i) {
            count += namedTypes[i].id != NULL;
        }
    } else if (kind == 1) {
        count = symbolCount;
    } else if (kind == 2) {
        count = variableCount;
    } else if (kind == 3) {
        for (int i = 0; i < referenceCount; ++i) {
            count += references[i].present;
        }
    } else if (kind == 4) {
        for (int i = 0; i < functionCount; ++i) {
            count += functions[i].present;
        }
    } else if (kind == 5) {
        for (int i = 0; i < tagReferenceCount; ++i) {
            count += tagReferences[i].tag != NULL;
        }
    } else if (kind == 6) {
        for (int i = 0; i < fieldCount; ++i) {
            count += fields[i].present;
        }
    }
    return count;
}

uint64_t ModelShape(BNType* type) {
    return type->shape;
}
