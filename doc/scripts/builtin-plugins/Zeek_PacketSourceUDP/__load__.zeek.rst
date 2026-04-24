:tocdepth: 3

builtin-plugins/Zeek_PacketSourceUDP/__load__.zeek
==================================================
.. zeek:namespace:: PacketSource::UDP

An opinionated Zeek packet source for the cloud.

:Namespace: PacketSource::UDP

Summary
~~~~~~~
Redefinable Options
###################
======================================================================================================================== =========================================================================
:zeek:id:`PacketSource::UDP::implementation`: :zeek:type:`PacketSource::UDP::ReceiverImplementation` :zeek:attr:`&redef` Which receiver implementation to usefor the UDP receiver
                                                                                                                         Can be one of PacketSource::UDP::RECVMMSG or
                                                                                                                         acketSource::UDP::IO_URING.
:zeek:id:`PacketSource::UDP::io_uring_buffer_shift`: :zeek:type:`count` :zeek:attr:`&redef`                              Shift value for the buffer size.
:zeek:id:`PacketSource::UDP::io_uring_buffers`: :zeek:type:`count` :zeek:attr:`&redef`                                   The number of buffers to for the ring.
:zeek:id:`PacketSource::UDP::io_uring_cq_entries`: :zeek:type:`count` :zeek:attr:`&redef`                                The number of entries in the completion queue.
:zeek:id:`PacketSource::UDP::io_uring_sq_entries`: :zeek:type:`count` :zeek:attr:`&redef`                                The number of entries in the submission queue.
:zeek:id:`PacketSource::UDP::poll_interval`: :zeek:type:`interval` :zeek:attr:`&redef`                                   Relax time for GetNextTimeout() when no packet was seen.
:zeek:id:`PacketSource::UDP::recvmmsg_buffer_size`: :zeek:type:`count` :zeek:attr:`&redef`                               The size of an individual packet buffer for the recvmmsg() mplementation.
:zeek:id:`PacketSource::UDP::recvmmsg_buffers`: :zeek:type:`count` :zeek:attr:`&redef`                                   The number of mmsghdrs to pass to recvmmsg() at once.
:zeek:id:`PacketSource::UDP::recvmmsg_use_selectable_fd`: :zeek:type:`bool` :zeek:attr:`&redef`                          Whether to use select on the socket to wake up Zeek's IO loop.
:zeek:id:`PacketSource::UDP::udp_recv_buffer_size`: :zeek:type:`count` :zeek:attr:`&redef`                               The size of the socket's UDP receive buffer to configure in bytes
======================================================================================================================== =========================================================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Redefinable Options
###################
.. zeek:id:: PacketSource::UDP::implementation
   :source-code: builtin-plugins/Zeek_PacketSourceUDP/__load__.zeek 9 9

   :Type: :zeek:type:`PacketSource::UDP::ReceiverImplementation`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``PacketSource::UDP::RECVMMSG``

   Which receiver implementation to usefor the UDP receiver
   Can be one of PacketSource::UDP::RECVMMSG or
   acketSource::UDP::IO_URING.

.. zeek:id:: PacketSource::UDP::io_uring_buffer_shift
   :source-code: builtin-plugins/Zeek_PacketSourceUDP/__load__.zeek 58 58

   :Type: :zeek:type:`count`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``14``

   Shift value for the buffer size. Default is 14, meaning
   a buffer size of (1 << 14) = 16KB. This covers jumbo packets and
   also has plenty of room for the SO_TIMESTAMP information as well.

.. zeek:id:: PacketSource::UDP::io_uring_buffers
   :source-code: builtin-plugins/Zeek_PacketSourceUDP/__load__.zeek 53 53

   :Type: :zeek:type:`count`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``1024``

   The number of buffers to for the ring.

.. zeek:id:: PacketSource::UDP::io_uring_cq_entries
   :source-code: builtin-plugins/Zeek_PacketSourceUDP/__load__.zeek 50 50

   :Type: :zeek:type:`count`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``256``

   The number of entries in the completion queue. Used with
   io_uring_queue_init_params()

.. zeek:id:: PacketSource::UDP::io_uring_sq_entries
   :source-code: builtin-plugins/Zeek_PacketSourceUDP/__load__.zeek 46 46

   :Type: :zeek:type:`count`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``2``

   The number of entries in the submission queue. We only
   submita single multishop RECVMSG op at a time, so keep
   this pretty small.

.. zeek:id:: PacketSource::UDP::poll_interval
   :source-code: builtin-plugins/Zeek_PacketSourceUDP/__load__.zeek 15 15

   :Type: :zeek:type:`interval`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``100.0 usecs``

   Relax time for GetNextTimeout() when no packet was seen.

   Applies to the IO_URING implementation. Applies to the RECVMMSG
   implementation only if recvmmsg_use_selectable_fd is F.

.. zeek:id:: PacketSource::UDP::recvmmsg_buffer_size
   :source-code: builtin-plugins/Zeek_PacketSourceUDP/__load__.zeek 41 41

   :Type: :zeek:type:`count`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``9248``

   The size of an individual packet buffer for the recvmmsg() mplementation.

   This is used for the iov_len field of an individual struct iovec.
   Defaults to 9216 + 32 bytes to cover jumbo packets and a bit of
   wiggle room for any extra encapsulation.

.. zeek:id:: PacketSource::UDP::recvmmsg_buffers
   :source-code: builtin-plugins/Zeek_PacketSourceUDP/__load__.zeek 34 34

   :Type: :zeek:type:`count`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``1024``

   The number of mmsghdrs to pass to recvmmsg() at once.

.. zeek:id:: PacketSource::UDP::recvmmsg_use_selectable_fd
   :source-code: builtin-plugins/Zeek_PacketSourceUDP/__load__.zeek 31 31

   :Type: :zeek:type:`bool`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``T``

   Whether to use select on the socket to wake up Zeek's IO loop.

   This applies to the recvmmsg() implementation only.

   If F, the packet source acts in polling mode which can
   be more efficient at high packet rates. However, this comes
   with a higher idle CPU usage due to the busy polling. See the
   oll_interval setting above, too. Read up on Zeek's internal
   io_poll_interval_live if you're considering tuning anything here.

.. zeek:id:: PacketSource::UDP::udp_recv_buffer_size
   :source-code: builtin-plugins/Zeek_PacketSourceUDP/__load__.zeek 20 20

   :Type: :zeek:type:`count`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``16777216``

   The size of the socket's UDP receive buffer to configure in bytes

   Set this value to ``0`` to use the kernel' default.


