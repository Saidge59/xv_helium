# HPT Architecture

This document gives a brief overview of the HPT architecture. Before reading
the code you should be comfortable with how kernels work, virtual memory,
processor atomic instructions, load/acquire semantics, and lockless ring buffers.

Important reference doc can be found a these two links:
  * https://www.kernel.org/doc/Documentation/memory-barriers.txt
  * https://www.kernel.org/doc/html/latest/core-api/circular-buffers.html).

## High Level Packet Flow

### Kernel -> Userspace

1. Kernel calls [`kernel/linux/hpt/hpt_net.c::hpt_net_tx()`](https://github.com/xvpn/xv_helium_tun/blob/13b5ef17b631ae645c85f0c81252fc9140210262/kernel/linux/hpt/hpt_net.c#L63)
2. `hpt_net_tx()` [emits to `hpt->tx_ring`](https://github.com/xvpn/xv_helium_tun/blob/13b5ef17b631ae645c85f0c81252fc9140210262/kernel/linux/hpt/hpt_net.c#L74) and [polls the device](https://github.com/xvpn/xv_helium_tun/blob/13b5ef17b631ae645c85f0c81252fc9140210262/kernel/linux/hpt/hpt_net.c#L85)
3. Listening device calls [`lib/hpt/hpt.c::hpt_drain()`](https://github.com/xvpn/xv_helium_tun/blob/13b5ef17b631ae645c85f0c81252fc9140210262/lib/hpt/hpt.c#L133)
4. `hpt_drain()` [takes from `hpt->tx_ring`](https://github.com/xvpn/xv_helium_tun/blob/13b5ef17b631ae645c85f0c81252fc9140210262/lib/hpt/hpt.c#L138) and [calls the user-provided read_cb](https://github.com/xvpn/xv_helium_tun/blob/13b5ef17b631ae645c85f0c81252fc9140210262/lib/hpt/hpt.c#L145)

### Userspace -> Kernel

1. Userspace calls [`lib/hpt/hpt.c::hpt_write()`](https://github.com/xvpn/xv_helium_tun/blob/13b5ef17b631ae645c85f0c81252fc9140210262/lib/hpt/hpt.c#L151)
2. Write [emits to `hpt->rx_ring`](https://github.com/xvpn/xv_helium_tun/blob/13b5ef17b631ae645c85f0c81252fc9140210262/lib/hpt/hpt.c#L153)
3. Our created kernel thread [`kernel/linux/hpt/hpt_core.c::hpt_kernel_thread()` calls `kernel/linux/hpt/hpt_net.c::hpt_net_rx()`](https://github.com/xvpn/xv_helium_tun/blob/13b5ef17b631ae645c85f0c81252fc9140210262/kernel/linux/hpt/hpt_core.c#L33)
4. `hpt_net_rx()` drains from [`hpt->rx_ring`](https://github.com/xvpn/xv_helium_tun/blob/13b5ef17b631ae645c85f0c81252fc9140210262/kernel/linux/hpt/hpt_net.c#L108) and [calls `netif_rx()`](https://github.com/xvpn/xv_helium_tun/blob/13b5ef17b631ae645c85f0c81252fc9140210262/kernel/linux/hpt/hpt_net.c#L155) for each item in `hpt->rx_ring`.

## Memory

To initialize a HPT device, a userspace program allocates memory for buffered
packets and metadata. HPT uses two ring buffers (or circular buffers),
described below.  The userspace program must allocate the precise amount of
space required for two rings, the transmit ring and the receive ring. This
memory must be allocated with `mmap`.

Within the library, you can find these functions defined in `lib/hpt/hpt.h`. An
example initialisation path would be:
```
int r = hpt_init(); // returns 0 on success
// tun_device_name something like `/dev/hpt`
struct hpt* hpt = hpt_alloc(tun_device_name, 8192, read_cb, handle);
```

`hpt_alloc` does the `mmap`, opens the device specificed by `tun_device_name`
and calls `ioctl`, passing the desired HPT configuration and the location of
memory. The kernel will then map the same memory into it's virtual address
space and initialize the rings.

Note that the `read_cb` is *not* automatically invoked as packets arrive.
Instead, as per "Eventing" below, the user program should call `hpt_drain` when
`EPOLLIN` is raised; `hpt_drain` then sequentially calls `read_cb` with each
ring buffer item.

The size of the rings is not included in the ring buffer structure since
it is constant at runtime and should not change. Any mutation of the length
could allow the userspace program to reach into arbitrary kernel memory.

## Ringbuffers

We implement single-producer, single-consumer ringbuffers for communication
between the kernel and userspace program, avoiding the need for syscalls to
pass data. These ring buffers can only be written to by a single process, and
only read by a single process, but they can be written safely while a read is
occurring and vice versa, i.e., it's safe for the single writer to be on one
thread and the singe writer to be on another without any locking.

`hpt_alloc` creates two ring buffers at initialization, one for TX and one for
RX. The TX ring buffer is written by the kernel and read by userspace (for
incoming packets), while the RX ring buffer is written by userspace and read by
the kernel (for outbound packets).

## TX path

The transmit path is called when a packet is sent from the kernel to our
HPT device. The HPT device will receive a function on the netdevice `xmit`
callback, defined in `kernel/linux/hpt/hpt_net.c::hpt_net_tx()`, and emit it to
`hpt->tx_ring`. It will then wake up any waiting processes by notifying `poll`
that the poll state has changed. In normal usage the userspace program would
then call `hpt_drain`, which would take items off of `hpt->tx_ring` and call
the user-provided `read_cb` in sequence.

## RX path

The receive path is written by userspace and picked up by a kernel thread. To
write a packet out, the userspace process calls `hpt_write`, which emits an
item to `hpt->rx_ring`. The kernel thread defined in
`kernel/linux/hpt/hpt_core.c::hpt_kernel_thread()` polls for work at a set
interval (in the microseconds) and if the ring buffer is not empty, it calls
`kernel/linbux/hpt/hpt_net.c::hpt_net_rx()`, which then takes the packet from
`hpt_rx_ring` and transmits it to the kernel network stack with a call to
`netif_rx_ni()`.

## Eventing

The HPT device driver implements `poll`, so to wait for new packets a userspace
program can use epollctl with the `EPOLLIN` event and the file descriptor
of the opened `/dev/hpt`. The device driver does not raise EPOLLOUT events,
if the driver is overloaded then the ring will fill up. The userspace program
can wait on failure or just discard packets at high load.
