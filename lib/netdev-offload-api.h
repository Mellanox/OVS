#ifndef _NETDEV_OFFLOAD_API_H_
#define _NETDEV_OFFLOAD_API_H_

#ifdef DPDK_NETDEV

#include "netdev-rte-offloads.h"

#define NETDEV_OFFLOAD_ADD_PORT(X,Y) netdev_rte_offload_add_port(X,Y)
#define NETDEV_OFFLOAD_DEL_PORT(X) netdev_rte_offload_del_port(X)


#define NETDEV_PREPROCCESS_PKT(X,Y) netdev_rte_offload_preprocess(X,Y)

#define OFFLOAD_RESERVED_MARK (64)

#else
// no dpdk no offload calls.,
#define NETDEV_OFFLOAD_ADD_PORT(X,Y) 
#define NETDEV_OFFLOAD_DEL_PORT(X) 
#define NETDEV_PREPROCCESS_PKT(X,Y) 
#define OFFLOAD_RESERVED_MARK (0)

#endif

static inline bool NETDEV_RTE_IS_OFFLOAD_RESERVED(uint32_t mark){
    return mark < OFFLOAD_RESERVED_MARK;
}



#endif
