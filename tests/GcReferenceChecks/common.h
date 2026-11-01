#pragma once

#include <cassert>
#include <cstddef>
#include <cstdint>
#include <cstring>

#ifdef _MSC_VER
#include <intrin.h>
using DWORD = unsigned long;
#endif

#define GCINFODECODER_NO_EE
#define FEATURE_NATIVEAOT
#define TARGET_AMD64
#define TARGET_64BIT
#define _ASSERTE assert
#define SUPPORTS_DAC
#define LIMITED_METHOD_CONTRACT
#define TRUE 1
#define FALSE 0
#define UINT32 uint32_t
#define INT32 int32_t
#define UINT16 uint16_t
#define UINT uint32_t
#define SIZE_T uintptr_t
#define SSIZE_T intptr_t
#define LPVOID void*
#define GC_CALL_INTERIOR 1
#define GC_CALL_PINNED 2

#ifdef _MSC_VER
#define NOINLINE __declspec(noinline)
#define ORACLE_EXPORT extern "C" __declspec(dllexport)
#else
#define NOINLINE __attribute__((noinline))
#define __forceinline inline __attribute__((always_inline))
#define ORACLE_EXPORT extern "C" __attribute__((visibility("default")))
#endif

using TADDR = uintptr_t;
using BOOL = int;
using OBJECTREF = void*;
using GCEnumCallback = void (*)(void*, OBJECTREF*, uint32_t);

// The decoder only reads these register pointers and SP. Values are synthetic
// disjoint addresses, so callbacks identify locations without a live process.
struct REGDISPLAY {
    uintptr_t* pRax;
    uintptr_t* pRcx;
    uintptr_t* pRdx;
    uintptr_t* pRbx;
    uintptr_t* pRbp;
    uintptr_t* pRsi;
    uintptr_t* pRdi;
    uintptr_t* pR8;
    uintptr_t* pR9;
    uintptr_t* pR10;
    uintptr_t* pR11;
    uintptr_t* pR12;
    uintptr_t* pR13;
    uintptr_t* pR14;
    uintptr_t* pR15;
    uintptr_t SP;
};
using PREGDISPLAY = REGDISPLAY*;

#include "gcinfo.h"

inline bool IS_ALIGNED(void* pointer, size_t alignment) {
    return ((uintptr_t)pointer & (alignment - 1)) == 0;
}
