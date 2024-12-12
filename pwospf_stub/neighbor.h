#pragma once
#include "sr_protocol.h"
#include "pwospf_protocol.h"
#include <mutex>
#include <cstring>
#include "sr_if.h"
#include "sr_rt.h"
#include <cassert>
#include <map>

namespace utils
{
    struct lsuInfo
    {
        uint32_t rid;         // this is the key in the adjList
        uint16_t seq;         // used to know when to update or not
        std::time_t timeout;  // the timeout of the LSU
        ospfv2_lsu routes[3]; // assuming per the spec that 3 routes will always be announced.
    };

    struct neighborInfo
    {
        uint32_t rid;
        uint32_t nmask;
        uint32_t subnet;
        uint32_t ipAddr;
        uint8_t mac[6];
        std::time_t timeout;
        char interface[SR_IFACE_NAMELEN];
        bool isStatic;
    };

    // pretty much all methods are blocking.
    class Topology
    {
    public:
        Topology()
        {
            ;
        }
        // return true if need to recalculate shortest path
        inline bool addLSU(uint8_t *packet)
        {

            std::lock_guard<std::mutex> lock(topoMutex);
            auto *ospfPkt = reinterpret_cast<ospfv2_hdr *>(packet + sizeof(sr_ethernet_hdr) + 20);

            auto len = adjList_.size();

            lsuInfo info;

            auto lsuHdr = reinterpret_cast<ospfv2_lsu_hdr *>(packet + sizeof(sr_ethernet_hdr) + sizeof(ip) + sizeof(ospfv2_hdr));

            auto existing = getLSUNonBlocking(ospfPkt->rid);
            auto routeChanged = false;
            auto routes = reinterpret_cast<ospfv2_lsu *>(packet + sizeof(sr_ethernet_hdr) + 20 + sizeof(ospfv2_hdr) + sizeof(ospfv2_lsu_hdr));

            if (existing)
            {
                // if newer sequence number
                if (existing->seq % ((2 ^ 16) - 1) >= lsuHdr->seq % ((2 ^ 16) - 1))
                {
                    return false;
                }
                if (std::memcmp(existing->routes, routes, 3 * sizeof(ospfv2_lsu)) != 0)
                {
                    routeChanged = true;
                }
            }

            std::memcpy(info.routes, routes, 3 * sizeof(ospfv2_lsu));

            info.rid = ospfPkt->rid;

            auto lsupkt = reinterpret_cast<ospfv2_lsu_hdr *>(packet + sizeof(sr_ethernet_hdr) + 20 + sizeof(ospfv2_hdr));

            info.seq = lsupkt->seq;

            assert(lsupkt->num_adv == htonl(3));
            info.timeout = std::time(NULL) + 3 * OSPF_DEFAULT_LSUINT;

            adjList_[ospfPkt->rid] = info;

            return adjList_.size() != len || routeChanged;
        }

        // if return true, trigger LSU if it needs to
        inline bool addHello(uint8_t *packet, char *interface, bool isStatic = false)
        {

            auto *ethPkt = reinterpret_cast<sr_ethernet_hdr *>(packet);
            std::lock_guard<std::mutex> lock(topoMutex);

            auto len = directNeighbors_.size();
            auto *ipPkt = reinterpret_cast<ip *>(ethPkt + sizeof(sr_ethernet_hdr));
            ospfv2_hdr *ospfPkt = reinterpret_cast<ospfv2_hdr *>(ethPkt + sizeof(sr_ethernet_hdr) + ipPkt->ip_hl * 4);
            auto helloPkt = reinterpret_cast<ospfv2_hello_hdr *>(ospfPkt + sizeof(sr_ethernet_hdr) + ipPkt->ip_hl * 4 + sizeof(ospfv2_hdr));

            auto subnet = ipPkt->ip_src.s_addr & helloPkt->nmask;

            bool ridChanged = false;
            auto existingSubnet = getHelloNonBlocking(subnet);
            if (existingSubnet)
                ridChanged = ospfPkt->rid == existingSubnet->rid;

            neighborInfo info;
            std::memcpy(info.interface, interface, SR_IFACE_NAMELEN);
            std::memcpy(info.mac, ethPkt->ether_shost, 6);
            info.timeout = std::time(NULL) + 3 * helloPkt->helloint;
            info.nmask = helloPkt->nmask;
            info.subnet = subnet;
            info.isStatic = isStatic;
            info.ipAddr = ipPkt->ip_src.s_addr;

            // subnet and the info
            directNeighbors_[subnet] = info;

            assert(directNeighbors_.size() <= 3);

            return ridChanged || directNeighbors_.size() != len;
        }

        // check the timeouts on directNeighbors. things. if they timed out, trigger a LSU
        inline bool refreshHello()
        {
            auto now = std::time(NULL);
            bool changed = false;
            for (auto it = directNeighbors_.begin(); it != directNeighbors_.end(); /* no increment*/)
            {
                if (it->second.timeout > now)
                {
                    Debug("HELLO had a timeout!\n");
                    directNeighbors_.erase(it++);
                    changed = true;
                }
                else
                {
                    ++it;
                }
            }
            return changed;
            // if changed, return true
        }

        // check the timeouts on things. if they timed out, trigger a new routing table calculation
        inline bool refreshLSU()
        {
            auto now = std::time(NULL);
            bool changed = false;

            for (auto it = adjList_.begin(); it != adjList_.end(); /* no increment*/)
            {
                if (it->second.timeout > now)
                {
                    adjList_.erase(it++);
                    changed = true;
                }
                else
                {
                    ++it;
                }
            }
            return changed;
            // if changed, return true
        }
        inline struct lsuInfo *getLSU(uint32_t rid)
        {
            std::lock_guard<std::mutex> lock(topoMutex);
            return getLSUNonBlocking(rid);
        }
        inline struct lsuInfo *getLSUNonBlocking(uint32_t rid)
        {

            const auto res = adjList_.find(rid);
            if (res != adjList_.end())
                return &(res->second);
            else
                return nullptr;
        }
        inline struct neighborInfo *getHello(uint32_t subnet)
        {
            std::lock_guard<std::mutex> lock(topoMutex);
            return getHelloNonBlocking(subnet);
        }
        inline struct neighborInfo *getHelloNonBlocking(uint32_t subnet)
        {
            const auto &res = directNeighbors_.find(subnet);
            if (res != directNeighbors_.end())
                return &(res->second);
            else
                return nullptr;
        }

        inline bool hasLSU(uint32_t rid)
        {
            std::lock_guard<std::mutex> lock(topoMutex);
            return adjList_.find(rid) != adjList_.end();
        }

        std::mutex topoMutex;

        std::map<uint32_t, neighborInfo> directNeighbors()
        {
            return directNeighbors_;
        }

    private:
        std::map<uint32_t, lsuInfo> adjList_;

        // keep these sorted so that lsu route announcements always occur in the same order.
        // if rids don't change, neither should the routes array (unless some other attribute
        // of them changed, which would be fine to trigger an update with)
        // this is the SUBNET to the hello info (get subnet via ippkt source & nmask)
        std::map<uint32_t, neighborInfo> directNeighbors_;
    };
}