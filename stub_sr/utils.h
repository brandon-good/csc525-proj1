#pragma once
#include <iostream>
#include "sr_protocol.h"
#include <ctime>

namespace utils
{
#ifndef ARPCACHE_TIMEOUT
#define ARPCACHE_TIMEOUT 10
#endif

    template <typename T>
    inline T byteswap(T value);
    template <>
    inline uint16_t byteswap<uint16_t>(uint16_t value)
    {
        return (value >> 8) | (value << 8);
    }

    struct arpcache_mac
    {
        std::time_t cache_time;
        std::string mac;
    };
}