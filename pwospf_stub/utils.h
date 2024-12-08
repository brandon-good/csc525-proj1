#pragma once
#include <iostream>
#include "sr_protocol.h"
#include <chrono>

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
        std::chrono::_V2::system_clock::time_point cache_time;
        std::string mac;
    };

    struct buffered_packet
    {
        uint8_t *packet;
        unsigned int len;
        char *interface;
    };
}