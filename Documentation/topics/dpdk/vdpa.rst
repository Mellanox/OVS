..
      Copyright (c) 2019 Mellanox Technologies, Ltd.

      Licensed under the Apache License, Version 2.0 (the "License");
      you may not use this file except in compliance with the License.
      You may obtain a copy of the License at:

          http://www.apache.org/licenses/LICENSE-2.0

      Unless required by applicable law or agreed to in writing, software
      distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
      WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
      License for the specific language governing permissions and limitations
      under the License.

      Convention for heading levels in Open vSwitch documentation:

      =======  Heading 0 (reserved for the title in a document)
      -------  Heading 1
      ~~~~~~~  Heading 2
      +++++++  Heading 3
      '''''''  Heading 4

      Avoid deeper levels because they do not render well.


===============
DPDK VDPA Ports
===============

In user space there are two main approaches to communicate with a guest (VM),
using virtIO ports (e.g. netdev type=dpdkvhoshuser/dpdkvhostuserclient) or
SR-IOV using phy ports (e.g. netdev type = dpdk).
Phy ports allow working with port representor which is attached to the OVS and
a matching VF is given with pass-through to the guest.
HW rules can process packets from up-link and direct them to the VF without
going through SW (OVS) and therefore using phy ports gives the best
performance.
However, SR-IOV architecture requires that the guest will use a driver which is
specific to the underlying HW. Specific HW driver has two main drawbacks:
1. Breaks virtualization in some sense (guest aware of the HW), can also limit
the type of images supported.
2. Less natural support for live migration.

Using virtIO port solves both problems, but reduces performance and causes
losing of some functionality, for example, for some HW offload, working
directly with virtIO cannot be supported.

We created a new netdev type- dpdkvdpa. dpdkvdpa port solves this conflict.
The new netdev is basically very similar to regular dpdk netdev but it has some
additional functionally.
This port translates between phy port to virtIO port, it takes packets from
rx-queue and send them to the suitable tx-queue and allows to transfer packets
from virtIO guest (VM) to a VF and vice versa and benefit both SR-IOV and
virtIO.

Quick Example
-------------

Configure OVS bridge and ports
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

you must first create a bridge and add ports to the switch.
Since the dpdkvdpa port is configured as a client, the vdpa-socket-path must be
configured by the user.
VHOST_USER_SOCKET_PATH=/path/to/socket

    $ ovs-vsctl add-br br0-ovs -- set bridge br0-ovs datapath_type=netdev
    $ ovs-vsctl add-port br0-ovs pf -- set Interface pf \
    type=dpdk options:dpdk-devargs=<pf pci id>
    $ ovs-vsctl add-port br0 vdpa0 -- set Interface vdpa0 type=dpdkvdpa \
    options:vdpa-socket-path=VHOST_USER_SOCKET_PATH \
    options:vdpa-accelerator-devargs=<vf pci id> \
    options:dpdk-devargs=<pf pci id>,representor=[id]

Once the ports have been added to the switch, they must be added to the guest.

Adding vhost-user ports to the guest (QEMU)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Attach the vhost-user device sockets to the guest. To do this, you must pass
the following parameters to QEMU:

    -chardev socket,id=char1,path=$VHOST_USER_SOCKET_PATH,server
    -netdev type=vhost-user,id=mynet1,chardev=char1,vhostforce
    -device virtio-net-pci,mac=00:00:00:00:00:01,netdev=mynet1

QEMU will wait until the port is created successfully in OVS to boot the VM.
In this mode, in case the switch will crash, the vHost ports will reconnect
automatically once it is brought back.
