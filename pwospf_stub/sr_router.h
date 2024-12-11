/*-----------------------------------------------------------------------------
 * File: sr_router.h
 * Date: ?
 * Authors: Guido Apenzeller, Martin Casado, Virkam V.
 * Contact: casado@stanford.edu
 *
 *---------------------------------------------------------------------------*/

#ifndef SR_ROUTER_H
#define SR_ROUTER_H

#include <netinet/in.h>
#include <sys/time.h>
#include <stdio.h>

#include "sr_protocol.h"
#include "pwospf_protocol.h"
#ifdef VNL
#include "vnlconn.h"
#endif

/* we dont like this debug , but what to do for varargs ? */
#ifdef _DEBUG_
#define Debug(x, args...) printf(x, ##args)
#define DebugMAC(x)                            \
    do                                         \
    {                                          \
        int ivyl;                              \
        for (ivyl = 0; ivyl < 5; ivyl++)       \
            printf("%02x:",                    \
                   (unsigned char)(x[ivyl]));  \
        printf("%02x", (unsigned char)(x[5])); \
    } while (0)
#else
#define Debug(x, args...) \
    do                    \
    {                     \
    } while (0)
#define DebugMAC(x) \
    do              \
    {               \
    } while (0)
#endif

#define INIT_TTL 255
#define PACKET_DUMP_SIZE 1024

/* forward declare */
struct sr_if;
struct sr_rt;

struct pwospf_subsys;

/* ----------------------------------------------------------------------------
 * struct sr_instance
 *
 * Encapsulation of the state for a single virtual router.
 *
 * -------------------------------------------------------------------------- */

struct sr_instance
{
    int sockfd; /* socket to server */
#ifdef VNL
    struct VnlConn *vc;
#endif
    char user[32];        /* user name */
    char host[32];        /* host name */
    char tmplate[30];     /* tmplate name if any */
    char auth_key_fn[64]; /* auth key filename */
    unsigned short topo_id;
    struct sockaddr_in sr_addr;  /* address to server */
    struct sr_if *if_list;       /* list of interfaces */
    struct sr_rt *routing_table; /* routing table */
    FILE *logfile;
    volatile uint8_t hw_init; /* bool : hardware has been initialized */

    /* -- pwospf subsystem -- */
    struct pwospf_subsys *ospf_subsys;
};

/* -- sr_main.c -- */
int sr_verify_routing_table(struct sr_instance *sr);

/* -- sr_vns_comm.c -- */
int sr_send_packet(struct sr_instance *, uint8_t *, unsigned int, const char *);
int sr_connect_to_server(struct sr_instance *, unsigned short, char *);
int sr_read_from_server(struct sr_instance *);

/* -- sr_router.c -- */
#ifdef __cplusplus

extern "C" void sr_init(struct sr_instance *);
extern "C" void sr_handlepacket(struct sr_instance *, uint8_t *, unsigned int, char *);
void incoming_process_as_arp(struct sr_instance *sr,
                             uint8_t *packet,
                             const unsigned int len,
                             const char *interface);
void incoming_arp_request(sr_instance *sr, uint8_t *packet, const unsigned int len, const char *interface);
void incoming_process_as_ip(sr_instance *sr, uint8_t *packet, const unsigned int len, char *);

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

inline uint16_t ospfv2_hdr_cksum(const struct ospfv2_hdr *hdr)
{
    return cksum(reinterpret_cast<const uint8_t *>(hdr), sizeof(ospfv2_hdr));
}

void neighborCleanup(sr_instance *sr);

#else
void sr_init(struct sr_instance *);
void sr_handlepacket(struct sr_instance *, uint8_t *, unsigned int, char *);
#endif
#ifndef CACHETIMEOUTSEC
#define CACHETIMEOUTSEC 10
#endif
/* -- sr_if.c -- */
void sr_add_interface(struct sr_instance *, const char *);
void sr_set_ether_ip(struct sr_instance *, uint32_t);
void sr_set_ether_addr(struct sr_instance *, const unsigned char *);
void sr_print_if_list(struct sr_instance *);

#endif /* SR_ROUTER_H */
