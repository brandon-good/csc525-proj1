/**********************************************************************
 * file:  sr_router.cc
 * date:  Mon Feb 18 12:50:42 PST 2002
 * Contact: casado@stanford.edu
 *
 * Description:
 *
 * This file contains all the functions that interact directly
 * with the routing table, as well as the main entry method
 * for routing.
 *
 * #693354266
 *
 **********************************************************************/

extern "C"
{
#include <stdio.h>
#include <assert.h>

#include "sr_if.h"
#include "sr_rt.h"
#include "sr_router.h"
#include "sr_pwospf.h"
}
#include "sr_protocol.h"

#include "utils.h"
#include <iostream>
#include <unordered_map>
#include <string>
#include <cstring>
#include <array>
#include <queue>
#include <mutex>

std::mutex routingMtx;
std::mutex neighborMtx;

std::unordered_map<in_addr_t, utils::arpcache_mac> ARPCACHE;
std::queue<utils::buffered_packet *> PACKET_BUFFER;

bool WAITING_FOR_ARP_REPLY = false;

/// @brief DONT USE THIS
/// @param buf POINTER TO packet
/// @param hdr_len total bytes to include
/// @return

// I want to copy the values here. The mem will get deleted if I do not, because the C functions clear the values.
inline void cache_put(in_addr_t ip, std::string mac)
{
    DebugMAC(mac.data());
    Debug(" CACHED to %s \n", inet_ntoa((in_addr){ip}));

    utils::arpcache_mac entry =
        {
            std::chrono::system_clock::now(), // now time
            mac,
        };

    ARPCACHE[ip] = entry;
}

inline std::string cache_get(in_addr_t ip)
{
    Debug("CHECKING CACHE FOR %s \n", inet_ntoa((in_addr){ip}));

    const auto result = ARPCACHE.find(ip);

    if (result != ARPCACHE.end())
    {
        // check time
        Debug("Cache is not empty. tdiff is %f\n", std::chrono::duration<double>(std::chrono::system_clock::now() - result->second.cache_time).count());
        if (std::chrono::duration<double>(std::chrono::system_clock::now() - result->second.cache_time).count() < CACHETIMEOUTSEC)
        {
            Debug("CACHE HIT!\n");
            DebugMAC(result->second.mac);
            Debug("\n");
            return result->second.mac;
        }
        else
        {
            Debug("CACHE TIMEOUT! Removing...\n");
            ARPCACHE.erase(ip);
        }
    }
    Debug("CACHE MISS!\n");
    return "";
}

/*---------------------------------------------------------------------
 * Method: sr_init(void)
 * Scope:  Global
 *
 * Initialize the routing subsystem
 *
 *---------------------------------------------------------------------*/

extern "C" void sr_init(struct sr_instance *sr)
{
    /* REQUIRES */
    assert(sr);

    /* Add initialization code here! */

} /* -- sr_init -- */

void buffer_packet(const uint8_t *packet, unsigned int len, const char *interface)
{
    uint8_t *heappacket = (uint8_t *)std::malloc(len);
    char *heapinterface = (char *)std::malloc(SR_IFACE_NAMELEN);
    utils::buffered_packet *bp = (utils::buffered_packet *)std::malloc(sizeof(utils::buffered_packet));
    assert(heappacket);
    assert(heapinterface);
    assert(bp);

    std::copy(packet, packet + len, heappacket);
    std::copy(interface, interface + SR_IFACE_NAMELEN, heapinterface);

    bp->packet = heappacket;
    bp->len = len;
    bp->interface = heapinterface;

    PACKET_BUFFER.push(bp);
}
inline utils::buffered_packet *get_buffer_packet()
{
    if (!PACKET_BUFFER.empty())
    {
        utils::buffered_packet *b = PACKET_BUFFER.front();
        PACKET_BUFFER.pop();
        return b;
    }
    Debug("packet buffer is empty\n");

    return nullptr;
}
/*---------------------------------------------------------------------
 * Method: sr_handlepacket(uint8_t* p,char* interface)
 * Scope:  Global
 *
 * This method is called each time the router receives a packet on the
 * interface.  The packet buffer, the packet length and the receiving
 * interface are passed in as parameters. The packet is complete with
 * ethernet headers.
 *
 * Note: Both the packet buffer and the character's memory are handled
 * by sr_vns_comm.c that means do NOT delete either.  Make a copy of the
 * packet instead if you intend to keep it around beyond the scope of
 * the method call.
 *
 *---------------------------------------------------------------------*/
extern "C" void sr_handlepacket(struct sr_instance *sr,
                                uint8_t *packet /* lent */,
                                unsigned int len,
                                char *interface /* lent */)
{
    assert(sr);
    assert(packet);
    assert(interface);
    printf("\n\n*** -> Received packet of length %d \n", len);

    // if we aren't waiting for an arp reply and have packets in the packet buffer, handle those first
    while (!WAITING_FOR_ARP_REPLY && !PACKET_BUFFER.empty())
    {
        utils::buffered_packet *b = get_buffer_packet();
        sr_handlepacket(sr, b->packet, b->len, b->interface);

        // if (b->packet)
        // {
        //     std::free(b->packet);
        // }
        // if (b->interface)
        // {
        //     std::free(b->interface);
        // }
        // if (b)
        // {
        //     std::free(b);
        // }
    }

    struct sr_ethernet_hdr *ethernet_packet = reinterpret_cast<struct sr_ethernet_hdr *>(packet);
    const auto ethernet_type = utils::byteswap(ethernet_packet->ether_type);

    switch (ethernet_type)
    {
    case ETHERTYPE_IP:
        Debug("ETHERNET PACKET TYPE IS IP\n");
        if (!WAITING_FOR_ARP_REPLY)
        {
            Debug("Calling incoming_process_as_ip\n");
            incoming_process_as_ip(sr, packet, len, interface);
        }
        else
        {
            Debug("BUFFERING IP PACKET\n");
            buffer_packet(packet, len, interface);
            return;
        }
        break;
    case ETHERTYPE_ARP:
        Debug("ETHERNET PACKET TYPE IS ARP\n");
        Debug("Calling incoming_process_as_arp\n\n\n ");
        incoming_process_as_arp(
            sr, packet, len, interface);
        break;

    default:
        Debug("TYPE OF ETHERNET PACKET IS UNKNOWN");
        Debug("ethernet_type is %d \n", ethernet_type);
        break;
    }

} /* end sr_ForwardPacket */

/*---------------------------------------------------------------------
 * Method: process_as_arp
 *  Process the arp packet.
 *
 *---------------------------------------------------------------------*/
void incoming_process_as_arp(struct sr_instance *sr,
                             uint8_t *packet,
                             const unsigned int len,
                             const char *interface)
{
    assert(packet);

    struct sr_arphdr *arp_packet = reinterpret_cast<struct sr_arphdr *>(packet + sizeof(struct sr_ethernet_hdr));
    // from slides 04-project
    assert(utils::byteswap(arp_packet->ar_hrd) == ARPHDR_ETHER);

    assert(utils::byteswap(arp_packet->ar_pro) == ETHERTYPE_IP);
    assert(arp_packet->ar_hln == 6);
    assert(arp_packet->ar_pln == 4);
    assert(sr);

    const auto arp_operation = utils::byteswap(arp_packet->ar_op);

    if (!WAITING_FOR_ARP_REPLY && arp_operation == ARP_REQUEST)
    {
        incoming_arp_request(sr, packet, len, interface);
    }
    else if (arp_operation == ARP_REPLY)
    {
        Debug("ARP OP IS REPLY\n");
        WAITING_FOR_ARP_REPLY = false;
        std::string cache_mac{reinterpret_cast<const char *>(arp_packet->ar_sha), ETHER_ADDR_LEN};

        cache_put(arp_packet->ar_sip, cache_mac);
        // process_arp_reply();}
    }
    else
    {
        buffer_packet(packet, len, interface);
        // we are waiting for a reply and it is a request
        // buffer the packet
    }
}

void incoming_arp_request(sr_instance *sr, uint8_t *packet, const unsigned int len, const char *interface)
{
    struct sr_ethernet_hdr *ethernet_packet = reinterpret_cast<struct sr_ethernet_hdr *>(packet);

    struct sr_arphdr *arp_packet = reinterpret_cast<struct sr_arphdr *>(packet + sizeof(struct sr_ethernet_hdr));
    Debug("ARP OP IS REQUEST\n");
    Debug("TARGET HW ADDR IS: ");
    DebugMAC(arp_packet->ar_tha);
    Debug("\n");
    Debug("TARGET IP ADDR %s \n", inet_ntoa((in_addr){arp_packet->ar_tip}));

    Debug("\n");
    Debug("SOURCE HW ADDR IS: ");
    DebugMAC(arp_packet->ar_sha);
    Debug("\n");
    Debug("SOURCE IP ADDR %s \n", inet_ntoa((in_addr){arp_packet->ar_sip}));
    Debug("\n");
    assert(std::memcmp(arp_packet->ar_tha, "\0\0\0\0\0", ETHER_ADDR_LEN) == 0);

    // cache the src hw and src ip

    std::string cache_mac{reinterpret_cast<const char *>(arp_packet->ar_sha), ETHER_ADDR_LEN};

    cache_put(arp_packet->ar_sip, cache_mac);

    // check the cache to see if we have a match there;
    std::string cache_hit{cache_get(arp_packet->ar_tip)};
    if (!cache_hit.empty())
    {
        // fill out with the cached info
        ;
    }
    else
    {
        // check to see if the target ip in the arp header matches an interface IP
        struct sr_if *if_walker = sr->if_list;
        while (if_walker)
        {
            if (arp_packet->ar_tip == if_walker->ip)
            {
                Debug("TARGET IP IS: %s WHICH MATCHES WITH %s\n", inet_ntoa((in_addr){arp_packet->ar_tip}), if_walker->name);
                break;
            }
            if_walker = if_walker->next;
        }

        if (if_walker) // then its a match
        {
            // need to send back info on the one it is connected to
            Debug("MATCH %s", if_walker->name);
            // this means the target ip matched one of the router's interfaces. get the interface info and send
            // an arp reply
            sr_if *connected_if = sr_get_interface(sr, interface);
            std::memcpy(ethernet_packet->ether_dhost, ethernet_packet->ether_shost, ETHER_ADDR_LEN);
            std::memcpy(ethernet_packet->ether_shost, connected_if->addr, ETHER_ADDR_LEN);
            uint16_t reply = ARP_REPLY;
            arp_packet->ar_op = utils::byteswap(reply);

            uint32_t tmp = arp_packet->ar_sip;
            arp_packet->ar_sip = connected_if->ip;
            arp_packet->ar_tip = tmp;

            std::memcpy(arp_packet->ar_tha, arp_packet->ar_sha, ETHER_ADDR_LEN);
            std::memcpy(arp_packet->ar_sha, connected_if->addr, ETHER_ADDR_LEN);

            if (sr_send_packet(sr, packet, len, connected_if->name))
            {
                return;
            }
            else
            {
                std::runtime_error{"send packet failed"};
            }
        }
        else
        {
            ; // do nothing, no match. Just drop the packet.
            return;
        }
    }
}

bool ip_on_router(struct sr_instance *sr, in_addr_t ip_addr)
{
    struct sr_if *if_walker = sr->if_list;
    while (if_walker)
    {
        if (ip_addr == if_walker->ip)
        {
            Debug("TARGET IP IS: %s WHICH MATCHES WITH %s\n", inet_ntoa((in_addr){ip_addr}), if_walker->name);
            return true;
        }
        if_walker = if_walker->next;
    }
    return false;
}
int send_icmp_reply(struct sr_instance *sr,
                    uint8_t *packet,
                    const unsigned int len,
                    const char *interface)
{
    struct sr_ethernet_hdr *ethernet_packet = reinterpret_cast<struct sr_ethernet_hdr *>(packet);
    struct ip *ip_packet = reinterpret_cast<struct ip *>(packet + sizeof(struct sr_ethernet_hdr));
    struct icmp_hdr *icmp = reinterpret_cast<struct icmp_hdr *>(packet + sizeof(struct sr_ethernet_hdr) + ip_packet->ip_hl * 4);

    sr_if *connected_if = sr_get_interface(sr, interface);

    std::memcpy(ethernet_packet->ether_dhost, ethernet_packet->ether_shost, ETHER_ADDR_LEN);
    std::memcpy(ethernet_packet->ether_shost, connected_if->addr, ETHER_ADDR_LEN);
    icmp->type = ICMP_ECHOREPLY;
    icmp->checksum = icmp_cksum(ip_packet, icmp, len);

    in_addr_t tmp = ip_packet->ip_src.s_addr;
    ip_packet->ip_src.s_addr = ip_packet->ip_dst.s_addr;
    ip_packet->ip_dst.s_addr = tmp;

    ip_packet->ip_sum = ip_cksum(ip_packet);

    assert(ip_cksum(ip_packet) == 0);
    assert(icmp_cksum(ip_packet, icmp, len) == 0);

    return sr_send_packet(sr, packet, len, connected_if->name);
}

bool longest_match(sr_rt *&rtable, ip *ip_packet)
{
    sr_rt *curr = rtable;
    bool match = false;
    while (curr)
    {
        if ((ip_packet->ip_dst.s_addr & curr->mask.s_addr) == (curr->dest.s_addr & curr->mask.s_addr))
        { // if this one is a match
            if (!match)
            {
                Debug("Found a match on %s\n", curr->interface);
                match = true;
                rtable = curr;
            }
            else if (match && (rtable->mask.s_addr < curr->mask.s_addr)) // if there has already been a match, see if the new mask is longer
            {
                Debug("Found a LONGER match on %s\n", curr->interface);
                rtable = curr;
            }
        }
        curr = curr->next;
    }

    return match;
}

void forward_ip_packet(struct sr_instance *sr,
                       std::string &dst_mac,
                       uint8_t *packet,
                       const unsigned int len,
                       const char *interface)
{
    Debug("we're here...........................");
    struct sr_ethernet_hdr *eth = reinterpret_cast<sr_ethernet_hdr *>(packet);
    sr_if *inter = sr_get_interface(sr, interface);

    std::memcpy(eth->ether_dhost, dst_mac.data(), ETHER_ADDR_LEN);
    std::memcpy(eth->ether_shost, inter->addr, ETHER_ADDR_LEN);

    struct ip *ip_packet = reinterpret_cast<struct ip *>(packet + sizeof(struct sr_ethernet_hdr));
    ip_packet->ip_sum = 0;
    ip_packet->ip_sum = ip_cksum(ip_packet);
    if (sr_send_packet(sr, packet, len, interface))
    {
        Debug("IP PACKET FORWARDED!\n");
        return;
    }
    else
    {
        std::runtime_error("IP PACKET FORWARD FAILED\n");
    }
}
void send_arp_request(struct sr_instance *sr,
                      uint32_t target_ip,
                      uint8_t *packet,
                      const unsigned int len,
                      const char *interface)
{
    size_t req_size = sizeof(sr_ethernet_hdr) + sizeof(sr_arphdr);
    uint8_t req[req_size];
    sr_if *inter = sr_get_interface(sr, interface);
    // fill out ethernet packet
    struct sr_ethernet_hdr *req_eth = reinterpret_cast<sr_ethernet_hdr *>(&req[0]);
    std::memcpy(req_eth->ether_dhost, "\xff\xff\xff\xff\xff\xff", ETHER_ADDR_LEN);
    std::memcpy(req_eth->ether_shost, inter->addr, ETHER_ADDR_LEN);
    req_eth->ether_type = utils::byteswap(uint16_t{ETHERTYPE_ARP});

    // fill out arp packet

    struct sr_arphdr *req_arp = reinterpret_cast<sr_arphdr *>(&req[sizeof(sr_ethernet_hdr)]);

    req_arp->ar_hrd = utils::byteswap(uint16_t{ARPHDR_ETHER});
    req_arp->ar_pro = utils::byteswap(uint16_t{ETHERTYPE_IP});
    req_arp->ar_hln = 6;
    req_arp->ar_pln = 4;
    req_arp->ar_op = utils::byteswap(uint16_t{ARP_REQUEST});

    std::memcpy(req_arp->ar_sha, inter->addr, ETHER_ADDR_LEN);
    req_arp->ar_sip = inter->ip;

    std::memcpy(req_arp->ar_tha, "\x00\x00\x00\x00\x00\x00", ETHER_ADDR_LEN);
    req_arp->ar_tip = target_ip;

    Debug("TARGET HW ADDR IS: ");
    DebugMAC(req_arp->ar_tha);
    Debug("\n");
    Debug("TARGET IP ADDR %s \n", inet_ntoa((in_addr){req_arp->ar_tip}));

    Debug("\n");
    Debug("SOURCE HW ADDR IS: ");
    DebugMAC(req_arp->ar_sha);
    Debug("\n");
    Debug("SOURCE IP ADDR %s \n", inet_ntoa((in_addr){req_arp->ar_sip}));
    Debug("\n");

    if (sr_send_packet(sr, req, req_size, interface))
    {
        Debug("ARP REQUEST SENT!\n");
        return;
    }
    else
    {
        std::runtime_error("the arp request didn't work");
    }
}

/// @brief process the incoming packet as an IP packet. Called by sr_handlepacket
/// @param sr router instance
/// @param packet incoming datagram
/// @param len length of the datagram
/// @param interface name of the interface the datagram was received on
void incoming_process_as_ip(struct sr_instance *sr,
                            uint8_t *packet,
                            const unsigned int len,
                            char *interface)
{
    // IP forwarding!
    // Check if dest addr is router's
    //     1. If ICMP echo reply, then reply
    //     2. Else, drop it
    // Decrement the TTL
    //     1. IF TTL is now 0, drop packet
    //     2. Otherwise, SET CHECKSUM TO 0, THEN CALCULATE HEADER CHECKSUM, then fill checksum field
    // Get LONGEST MATCH
    // Send to next hop out of the corresponding outgoing interface (in routing table)
    struct ip *ip_packet = reinterpret_cast<struct ip *>(packet + sizeof(struct sr_ethernet_hdr));
    ip_packet->ip_sum = 0;

    if (--(ip_packet->ip_ttl) <= 0)
    {
        Debug("TTL is 0! Dropping the packet \n");
        return; // if the TTL is 0, drop the packet
    };

    if (ip_packet->ip_p == IPPROTO_ICMP && ip_on_router(sr, ip_packet->ip_dst.s_addr))
    {
        Debug("received an ICMP packet\n");
        struct icmp_hdr *icmp = reinterpret_cast<struct icmp_hdr *>(packet + sizeof(struct sr_ethernet_hdr) + ip_packet->ip_hl * 4);
        icmp->checksum = 0;
        // Debug("cksum: %d \n", icmp->checksum);
        // Debug("type:  %d\n", icmp->type);
        // Debug("code: %d\n", icmp->code);
        if (icmp->code == ICMP_CODE && icmp->type == ICMP_ECHO)
        {
            Debug("ICMP packet is a REQUEST\n");
            if (send_icmp_reply(sr, packet, len, interface))
            {
                return;
            }
            else
            {
                std::runtime_error{"tears"};
            }
        }
        else
        {
            return; // drop the packet
        }
    }
    else if (ip_packet->ip_p == OSPF_IP_PROTO && ip_packet->ip_dst.s_addr == OSPF_AllSPFRouters)
    {
        // we are receiving a Hello packet
        // check the version
        // verify the cksum (zero out the authentification)
        // check the auth type
        // update the routing table with the helloint and
    }
    else
    {
        // IP packet forwarding
        sr_rt *rtable = sr->routing_table;
        longest_match(rtable, ip_packet);

        in_addr_t nexthop = rtable->gw.s_addr;
        Debug("  nexthop is %s \n", inet_ntoa((in_addr){nexthop}));

        if (rtable->gw.s_addr == 0)
        {
            nexthop = ip_packet->ip_dst.s_addr;
            Debug("    so nexthop was reset to %s \n", inet_ntoa((in_addr){nexthop}));
        }
        // see if you have the mac in your arpcache
        std::string dst_mac = cache_get(nexthop);
        if (dst_mac.empty())
        {
            Debug("prepping an ARP request...buffering all other incoming packets\n");
            // BUFFER THIS PACKET
            buffer_packet(packet, len, interface);
            WAITING_FOR_ARP_REPLY = true;
            send_arp_request(sr,
                             nexthop,
                             packet,
                             len,
                             rtable->interface);
        }
        else
        {
            Debug("we have that cached!\n");
            forward_ip_packet(sr, dst_mac, packet, len, rtable->interface);
        }
    }
}
