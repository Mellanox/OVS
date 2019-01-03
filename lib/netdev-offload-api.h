#ifndef _NETDEV_OFFLOAD_API_H_
#define _NETDEV_OFFLOAD_API_H_

#ifdef DPDK_NETDEV

#include "netdev-rte-offloads.h"

#define NETDEV_OFFLOAD_ADD_PORT(X,Y) netdev_rte_offload_add_port(X,Y)
#define NETDEV_OFFLOAD_DEL_PORT(X) netdev_rte_offload_del_port(X)

#define OFFLOAD_RESERVED_MARK (64)

#else

#define NETDEV_OFFLOAD_ADD_PORT(X,Y)
#define NETDEV_OFFLOAD_DEL_PORT(X)
#define OFFLOAD_RESERVED_MARK (0)

#endif



#endif
