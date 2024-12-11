/*-----------------------------------------------------------------------------
 * file:  sr_rt.h
 * date:  Mon Oct 07 03:53:53 PDT 2002
 * Author: casado@stanford.edu
 *
 * Description:
 *
 * Methods and datastructures for handeling the routing table
 *
 *---------------------------------------------------------------------------*/

#ifndef sr_RT_H
#define sr_RT_H

#ifdef _DARWIN_
#include <sys/types.h>
#endif

#include <netinet/in.h>
#include <time.h>
#include "sr_if.h"

/* ----------------------------------------------------------------------------
 * struct sr_rt
 *
 * Node in the routing table
 *
 * -------------------------------------------------------------------------- */

struct sr_rt
{
    struct in_addr dest;
    struct in_addr gw;
    struct in_addr mask;
    char interface[SR_IFACE_NAMELEN];
    uint8_t isStatic;
    uint16_t helloInt;
    time_t refreshTime;
    struct sr_rt *next;
};

#ifndef RTABLE_ENTRY_STATIC
#define RTABLE_ENTRY_STATIC 0
#endif

#ifndef RTABLE_ENTRY_DYNAMIC
#define RTABLE_ENTRY_DYNAMIC 1
#endif

int sr_load_rt(struct sr_instance *, const char *);
void sr_add_rt_entry(struct sr_instance *, struct in_addr, struct in_addr,
                     struct in_addr, char *);
void sr_print_routing_table(struct sr_instance *sr);
void sr_print_routing_entry(struct sr_rt *entry);

#endif /* --  sr_RT_H -- */
