#pragma once

#define DPTR(type) type*
#define ArrayDPTR(type) type*

using PTR_VOID = void*;
using PTR_size_t = size_t*;
using PTR_uintptr_t = uintptr_t*;

template<class Target, class Source> Target dac_cast(Source value) {
    return (Target)value;
}
