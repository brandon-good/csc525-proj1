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
}
#include "sr_protocol.h"

#include "utils.h"
#include <iostream>
#include <unordered_map>
#include <string>
#include <cstring>
#include <array>

std::unordered_map<in_addr_t, utils::arpcache_mac> ARPCACHE;

bool WAITING = false;

/// @brief DONT USE THIS
/// @param buf POINTER TO packet
/// @param hdr_len total bytes to include
/// @return
inline uint16_t cksum(const uint8_t *packet, size_t hdr_len)
{
    int two_byte_words = hdr_len / 2;
    const uint16_t *two_byte_buff = reinterpret_cast<const uint16_t *>(packet);

    uint32_t sum = 0;
    while (two_byte_words--)
    {
        sum += (*two_byte_buff);
        two_byte_buff++;
        if (sum >> 16)
        {
            sum = (sum & 0xFFFF) + (sum >> 16);
        }
    }
    sum = ~(sum & 0xFFFF);
    return sum;
}

inline uint16_t icmp_cksum(const struct ip *i, const struct icmp_hdr *icmp, size_t len)
{
    return cksum(reinterpret_cast<const uint8_t *>(icmp), len - sizeof(sr_ethernet_hdr) - 4 * i->ip_hl);
}

inline uint16_t ip_cksum(const struct ip *i)
{
    return cksum(reinterpret_cast<const uint8_t *>(i), 4 * i->ip_hl);
}
// I want to copy the values here. The mem will get deleted if I do not, because the C functions clear the values.
inline void cache_put(in_addr_t ip, std::string mac)
{
    DebugMAC(mac.data());
    Debug(" CACHED to %s \n", inet_ntoa((in_addr){ip}));

    utils::arpcache_mac entry =
        {
            std::time(nullptr), // now time
            mac,
        };

    ARPCACHE[ip] = entry;
}

inline std::string cache_get(in_addr_t ip)
{
    Debug("CHECKING CACHE FOR %s \n", inet_ntoa((in_addr){ip}));

    auto result = ARPCACHE.find(ip);

    if (result != ARPCACHE.end())
    {
        // check time
        if (std::time(nullptr) - result->second.cache_time > CACHETIMEOUTSEC)
        {
            Debug("CACHE HIT! ");
            DebugMAC(result->second.mac);
            Debug("\n");
            return result->second.mac;
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
    /* REQUIRES */
    assert(sr);
    assert(packet);
    assert(interface);
    printf("\n\n*** -> Received packet of length %d \n", len);
    struct sr_ethernet_hdr *ethernet_packet = reinterpret_cast<struct sr_ethernet_hdr *>(packet);
    const auto ethernet_type = utils::byteswap(ethernet_packet->ether_type);

    switch (ethernet_type)
    {
    case ETHERTYPE_IP:
        Debug("ETHERNET PACKET TYPE IS IP\n");
        Debug("Calling incoming_process_as_ip\n");
        incoming_process_as_ip(sr, packet, len, interface);
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

    auto arp_operation = utils::byteswap(arp_packet->ar_op);
    switch (arp_operation)
    {
    case ARP_REQUEST:
    {
        incoming_arp_request(sr, packet, len, interface);
        break;
    }
    case ARP_REPLY:
        Debug("ARP OP IS REPLY");
        // process_arp_reply();
        break;
    default:
        break;
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
    assert(std::memcmp(arp_packet->ar_tha, "\0\0\0", ETHER_ADDR_LEN) == 0);

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
                std::runtime_error{"tears"};
            }
        }
        else
        {
            ; // do nothing, no match. Just drop the packet.
            return;
        }

        // std::string cache_mac{reinterpret_cast<const char *>(arp_packet->ar_sha), ETHER_ADDR_LEN};

        // if match, send response with mac addr of interface that matched
        // if no match, do nothing

        // process ARP Request
        //  1. check the cache for a match
        //  2. look at the target IP, and get the subnet
        //  3. see if subnet is in your routing table
        //  4. if it is, send an ARP reply with the MAC addr of the interface that the arp request came through
        //  5. Send out an ARP request for the next hop mac addr for that IP, cache result
        //  5. Get an IP Packet?
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

/// @brief process the incoming packet as an IP packet. Called by sr_handlepacket
/// @param sr router instance
/// @param packet incoming datagram
/// @param len length of the datagram
/// @param interface name of the interface the datagram was received on
void incoming_process_as_ip(struct sr_instance *sr,
                            uint8_t *packet,
                            const unsigned int len,
                            const char *interface)
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
    struct sr_ethernet_hdr *ethernet_packet = reinterpret_cast<struct sr_ethernet_hdr *>(packet);
    ip_packet->ip_sum = 0;

    if (--(ip_packet->ip_ttl) <= 0)
    {
        return; // if the TTL is 0, drop the packet
    };

    if (ip_on_router(sr, ip_packet->ip_dst.s_addr) && ip_packet->ip_p == IPPROTO_ICMP)
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
            return;
        }
    }
    else
    {
        //
    }
}