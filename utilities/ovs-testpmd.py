#!/usr/bin/env python

# pf is port-flow
# for each port we keep a list of id/rte_flow pairs (flat list), as
# dpdk's testpmd does.
# each added flow pushes its pair to the list, increasing the ID
# from the last one. destroy searches the rte_flow in the list to
# print the right rule number, and removes the pair from the list.

NUM_OF_PORTS = 10
pf = [list([])] * NUM_OF_PORTS

def create(split, rte_flow):
    port = int(split[split.index('create') + 1])
    if not pf[port]:
        id = 0
    else:
        id = pf[port][0] + 1
    pf[port] = [id, rte_flow] + pf[port]
    line = ' '.join(split[split.index('flow'):])
    print(line)

def destroy(split, rte_flow):
    port = int(split[split.index('destroy') + 1])
    if not rte_flow in pf[port]:
        print split
        return
    rte_flow_ind = pf[port].index(rte_flow)
    id = pf[port][rte_flow_ind - 1]
    pf[port] = pf[port][:rte_flow_ind-1] + pf[port][rte_flow_ind+1:]
    line = ' '.join(split[split.index('flow'):]) + ' ' + str(id)
    print(line)

filepath = '/var/log/openvswitch/ovs-vswitchd.log'
with open(filepath) as fp:
    line = fp.readline()
    while line:
        ind = line.find("testpmd")
        if ind < 0:
            line = fp.readline()
            continue
        split = line.split()
        rte_flow = split[split.index('rte_flow') + 1]
        if line.find('create') >= 0:
            create(split, rte_flow)
        if line.find('destroy') >= 0:
            destroy(split, rte_flow)
        line = fp.readline()

