:orphan:

Package: base/frameworks/broker
===============================

The Broker communication framework facilitates connecting to remote Zeek
instances to share state and transfer events.

:doc:`/scripts/base/frameworks/broker/__load__.zeek`


:doc:`/scripts/base/frameworks/broker/main.zeek`

   The Broker-based communication API and its various options.

:doc:`/scripts/base/frameworks/broker/store.zeek`

   The Broker-based data store API and its various options.

:doc:`/scripts/base/frameworks/broker/log.zeek`


:doc:`/scripts/base/frameworks/broker/backpressure.zeek`

   This handles Broker peers that fall so far behind in handling messages that
   this node sends it that the local Broker endpoint decides to unpeer them.
   Zeek captures this as follows:
   
   - In broker.log, with a regular "peer-removed" entry indicating CAF's reason.
   - Via eventing through :zeek:see:`Broker::peer_removed` as done in this script.
   
   The cluster framework additionally captures the unpeering as follows:
   
   - In cluster.log, with a higher-level message indicating the node names involved.
   - Via telemetry, using a labeled counter.

