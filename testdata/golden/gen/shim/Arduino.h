#pragma once

// Host-side stand-in for the few Arduino bits the reference helpers
// touch (AdvertTimeHelper only formats with sprintf).

#include <cstdint>
#include <cstdio>
#include <cmath>
#include "Stream.h"

inline uint32_t millis() { return 0; }
