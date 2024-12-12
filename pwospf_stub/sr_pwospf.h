/*-----------------------------------------------------------------------------
 * file:  sr_pwospf.h
 * date:  Tue Nov 23 23:21:22 PST 2004
 * Author: Martin Casado
 *
 * Description:
 *
 *---------------------------------------------------------------------------*/

#ifndef SR_PWOSPF_H
#define SR_PWOSPF_H

#include <pthread.h>
#include <stdint.h>

#include "sr_router.h"
#include "pwospf_protocol.h"

/* forward declare */
struct sr_instance;

struct pwospf_subsys
{
    /* -- pwospf subsystem state variables here -- */
    uint16_t helloint;
    uint32_t rid;

    /* -- thread and single lock for pwospf subsystem -- */
    pthread_t thread;
    pthread_mutex_t lock;
};

#ifdef __cplusplus

typedef uint32_t routerId;

extern "C" int pwospf_init(struct sr_instance *);
// look at each interfaces helloNeighbor and see if the time since the last refresh
// is greater than 3times the helloint duration
#else
int pwospf_init(struct sr_instance *);
#endif
#ifndef OSPF_IP_PROTO
#define OSPF_IP_PROTO 89
#endif

#endif /* SR_PWOSPF_H */
