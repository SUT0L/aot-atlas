#include "common.h"
#include <algorithm>
#include <cstdio>
#include <cstdlib>
#include <vector>

#define ORACLE_FUNCTION gc_decode
namespace CurrentRuntime {
#include "gcinfodecoder.cpp"
#include "bridge.cpp"

ORACLE_EXPORT uint32_t gc_reference_abi_version() {
    return 2;
}
}
