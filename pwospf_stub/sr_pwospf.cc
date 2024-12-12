/*-----------------------------------------------------------------------------
 * file: sr_pwospf.c
 * date: Tue Nov 23 23:24:18 PST 2004
 * Author: Martin Casado
 *
 * Description:
 *
 *---------------------------------------------------------------------------*/

extern "C"
{
#include <stdio.h>
#include <unistd.h>
#include <assert.h>
#include <stdlib.h>
#include <time.h>

#include "sr_pwospf.h"
#include "sr_if.h"
#include "sr_rt.h"
}
#include <cstring>
#include <mutex>
#include "utils.h"

uint16_t SEQNUM = 0;
/* -- declaration of main thread function for pwospf subsystem --- */
void *pwospf_run_thread(void *arg);

/*---------------------------------------------------------------------
 * Method: pwospf_init(..)
 *
 * Sets up the internal data structures for the pwospf subsystem
 *
 * You may assume that the interfaces have been created and initialized
 * by this point.
 *---------------------------------------------------------------------*/

extern "C" int pwospf_init(struct sr_instance *sr)
{
    assert(sr);

    sr->ospf_subsys = (struct pwospf_subsys *)malloc(sizeof(struct
                                                            pwospf_subsys));

    assert(sr->ospf_subsys);
    pthread_mutex_init(&(sr->ospf_subsys->lock), 0);

    /* -- handle subsystem initialization here! -- */
    sr->ospf_subsys->helloint = OSPF_DEFAULT_HELLOINT;
    auto eth0 = sr_get_interface(sr, "eth0");

    sr->ospf_subsys->rid = eth0->ip;

    /* -- start thread subsystem -- */
    if (pthread_create(&sr->ospf_subsys->thread, 0, pwospf_run_thread, sr))
    {
        perror("pthread_create");
        assert(0);
    }

    return 0; /* success */
} /* -- pwospf_init -- */

/*---------------------------------------------------------------------
 * Method: pwospf_lock
 *
 * Lock mutex associated with pwospf_subsys
 *
 *---------------------------------------------------------------------*/

void pwospf_lock(struct pwospf_subsys *subsys)
{
    if (pthread_mutex_lock(&subsys->lock))
    {
        assert(0);
    }
} /* -- pwospf_subsys -- */

/*---------------------------------------------------------------------
 * Method: pwospf_unlock
 *
 * Unlock mutex associated with pwospf subsystem
 *
 *---------------------------------------------------------------------*/

void pwospf_unlock(struct pwospf_subsys *subsys)
{
    if (pthread_mutex_unlock(&subsys->lock))
    {
        assert(0);
    }
} /* -- pwospf_subsys -- */

void send_hello_pkts(sr_instance *sr)
{
    pwospf_lock(sr->ospf_subsys);

    auto rtrIf = sr->if_list;

    while (rtrIf)
    {
        unsigned int len = sizeof(sr_ethernet_hdr) + 20 + sizeof(ospfv2_hdr) + sizeof(ospfv2_hello_hdr);
        uint8_t *datapacket = static_cast<uint8_t *>(calloc(len, 1));

        // ethernet
        sr_ethernet_hdr *ethernetHdr = reinterpret_cast<sr_ethernet_hdr *>(datapacket);
        std::memcpy(ethernetHdr->ether_shost, rtrIf->addr, ETHER_ADDR_LEN);
        std::memcpy(ethernetHdr->ether_dhost, "\xff\xff\xff\xff\xff\xff", ETHER_ADDR_LEN);
        ethernetHdr->ether_type = htons(ETHERTYPE_IP);
        /////

        // ip
        ip *ipHdr = reinterpret_cast<ip *>(datapacket + sizeof(struct sr_ethernet_hdr));
        ipHdr->ip_v = 4;
        ipHdr->ip_hl = 5;
        ipHdr->ip_tos = 0;
        ipHdr->ip_len = htons(len - sizeof(struct sr_ethernet_hdr));
        ipHdr->ip_id = 0;
        ipHdr->ip_off = htons(IP_DF);
        ipHdr->ip_ttl = 64;
        ipHdr->ip_p = OSPF_IP_PROTO;
        ipHdr->ip_sum = 0;
        ipHdr->ip_src.s_addr = rtrIf->ip;
        ipHdr->ip_dst.s_addr = htonl(OSPF_AllSPFRouters);

        ipHdr->ip_sum = ip_cksum(ipHdr);
        /////

        // ospf
        ospfv2_hdr *ospfHdr = reinterpret_cast<ospfv2_hdr *>(datapacket + sizeof(sr_ethernet_hdr) + 20);
        ospfHdr->version = OSPF_V2;
        ospfHdr->type = OSPF_TYPE_HELLO;
        ospfHdr->len = htons(sizeof(ospfv2_hdr) + sizeof(ospfv2_hello_hdr));
        ospfHdr->rid = sr->ospf_subsys->rid;
        ospfHdr->aid = OSPF_DEFAULT_AID;
        ospfHdr->csum = 0;
        ospfHdr->autype = OSPF_DEFAULT_AUTHTYPE;
        ospfHdr->audata = OSPF_DEFAULT_AUTHDATA;

        ospfHdr->csum = ospfv2_hdr_cksum(ospfHdr);
        /////

        // ospf hello
        ospfv2_hello_hdr *helloHdr = reinterpret_cast<ospfv2_hello_hdr *>(datapacket + sizeof(sr_ethernet_hdr) + 20 + sizeof(ospfv2_hdr));
        helloHdr->helloint = htons(sr->ospf_subsys->helloint);
        helloHdr->nmask = htonl(rtrIf->mask);
        helloHdr->padding = 0;
        /////

        sr_send_packet(sr, datapacket, len, rtrIf->name);
        Debug("hello sent...\n");
        if (datapacket)
            free(datapacket);
        rtrIf = rtrIf->next;
    }
    pwospf_unlock(sr->ospf_subsys);
}

void send_lsu_pkts(sr_instance *sr)
{
    Debug("sending LSU packets...\n");
    SEQNUM++;
    pwospf_lock(sr->ospf_subsys);

    std::lock_guard<std::mutex> lock(Topo.topoMutex);
    auto neighbors = Topo.directNeighbors();

    for (const auto &pair : neighbors)
    {
        if (pair.second.rid == 0)
            continue;
        auto len = sizeof(sr_ethernet_hdr) + 20 + sizeof(ospfv2_hdr) + sizeof(ospfv2_lsu_hdr) + 3 * sizeof(ospfv2_lsu);
        uint8_t *datapacket = static_cast<uint8_t *>(calloc(len, 1));

        auto rtrIf = sr_get_interface(sr, pair.second.interface);
        // ethernet
        sr_ethernet_hdr *ethernetHdr = reinterpret_cast<sr_ethernet_hdr *>(datapacket);
        std::memcpy(ethernetHdr->ether_shost, rtrIf->addr, ETHER_ADDR_LEN);
        std::memcpy(ethernetHdr->ether_dhost, pair.second.mac, ETHER_ADDR_LEN);
        ethernetHdr->ether_type = htons(ETHERTYPE_IP);
        /////

        // ip
        ip *ipHdr = reinterpret_cast<ip *>(datapacket + sizeof(struct sr_ethernet_hdr));
        ipHdr->ip_v = 4;
        ipHdr->ip_hl = 5;
        ipHdr->ip_tos = 0;
        ipHdr->ip_len = htons(len - sizeof(sr_ethernet_hdr));
        ipHdr->ip_id = 0;
        ipHdr->ip_off = htons(IP_DF);
        ipHdr->ip_ttl = 64;
        ipHdr->ip_p = OSPF_IP_PROTO;
        ipHdr->ip_sum = 0;
        ipHdr->ip_src.s_addr = rtrIf->ip;
        ipHdr->ip_dst.s_addr = pair.second.ipAddr;

        ipHdr->ip_sum = ip_cksum(ipHdr);
        /////

        // ospf
        ospfv2_hdr *ospfHdr = reinterpret_cast<ospfv2_hdr *>(datapacket + sizeof(sr_ethernet_hdr) + 20);
        ospfHdr->version = OSPF_V2;
        ospfHdr->type = OSPF_TYPE_LSU;
        ospfHdr->len = htons(sizeof(ospfv2_hdr) + sizeof(ospfv2_lsu_hdr) + 3 * sizeof(ospfv2_lsu));
        ospfHdr->rid = sr->ospf_subsys->rid;
        ospfHdr->aid = OSPF_DEFAULT_AID;
        ospfHdr->csum = 0;
        ospfHdr->autype = OSPF_DEFAULT_AUTHTYPE;
        ospfHdr->audata = OSPF_DEFAULT_AUTHDATA;

        ospfHdr->csum = ospfv2_hdr_cksum(ospfHdr);
        /////

        // ospf LSU Hdr
        ospfv2_lsu_hdr *lsuHdr = reinterpret_cast<ospfv2_lsu_hdr *>(datapacket + sizeof(sr_ethernet_hdr) + 20 + sizeof(ospfv2_hdr));
        lsuHdr->num_adv = htonl(3);
        lsuHdr->seq = SEQNUM;
        lsuHdr->ttl = OSPF_MAX_LSU_TTL;
        ospfv2_lsu *lsu = reinterpret_cast<ospfv2_lsu *>(datapacket + sizeof(sr_ethernet_hdr) + 20 + sizeof(ospfv2_hdr) + sizeof(ospfv2_lsu_hdr));

        for (const auto &pair2 : neighbors)
        {
            lsu->mask = pair2.second.nmask;
            lsu->rid = pair2.second.rid;
            lsu->subnet = pair2.second.subnet;
            lsu += sizeof(ospfv2_lsu);
        }

        assert(lsuHdr->ttl == OSPF_MAX_LSU_TTL);
        sr_send_packet(sr, datapacket, len, rtrIf->name);
        if (datapacket)
            free(datapacket);
    }
    pwospf_unlock(sr->ospf_subsys);
}

/*---------------------------------------------------------------------
 * Method: pwospf_run_thread
 *
 * Main thread of pwospf subsystem.
 *
 *---------------------------------------------------------------------*/

void *pwospf_run_thread(void *arg)
{
    struct sr_instance *sr = (struct sr_instance *)arg;
    auto ii = 0;
    while (1)
    {
        /* -- PWOSPF subsystem functionality should start  here! -- */

        // check for stale entries
        // use area id 0
        // rid is the source ip out the interface
        // OSPFv2 packets are all IP packets
        pwospf_lock(sr->ospf_subsys);

        // send a broadcast ethernet packet with ip dest of AllSPFRouters as the dest ip and 0xffffffff as the dest mac
        // check timeouts and send hello packets no matter what
        Topo.refreshHello();
        pwospf_unlock(sr->ospf_subsys);

        send_hello_pkts(sr);

        if (ii == 6)
        {
            pwospf_lock(sr->ospf_subsys);

            // check timeouts and send lsu packets no matter what
            Debug("...periodic refresh of lsu from ospf thread...\n");
            Topo.refreshLSU();
            pwospf_unlock(sr->ospf_subsys);

            send_lsu_pkts(sr);
            ii = 0;
        }
        ii++;
        // build packet

        sleep(OSPF_DEFAULT_HELLOINT);
    };
    return NULL;
} /* -- run_ospf_thread -- */
