#include "common.h"
#include <algorithm>
#include <cstdio>
#include <cstdlib>
#include <vector>

// The runtime supports old encodings through this build flag. Keep that build
// isolated: the current-format runtime normally compiles without the flag.
#define DECODE_OLD_FORMATS
#define ORACLE_FUNCTION gc_decode_legacy
namespace LegacyRuntime {
#include "gcinfodecoder.cpp"
#include "bridge.cpp"
}
