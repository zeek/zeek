:tocdepth: 3

base/protocols/ntp/consts.zeek
==============================
.. zeek:namespace:: NTP


:Namespace: NTP

Summary
~~~~~~~
Redefinable Options
###################
================================================================================================================================== ====================================================
:zeek:id:`NTP::modes`: :zeek:type:`table` :zeek:attr:`&default` = :zeek:type:`function` :zeek:attr:`&optional` :zeek:attr:`&redef` The descriptions of the NTP mode value, as described
                                                                                                                                   in :rfc:`5905`, Figure 1
================================================================================================================================== ====================================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Redefinable Options
###################
.. zeek:id:: NTP::modes

   :Type: :zeek:type:`table` [:zeek:type:`count`] of :zeek:type:`string`
   :Attributes: :zeek:attr:`&default` = :zeek:type:`function` :zeek:attr:`&optional` :zeek:attr:`&redef`
   :Default:

   ::

      {
         [2] = "symmetric passive",
         [6] = "broadcast client",
         [4] = "server",
         [1] = "symmetric active",
         [7] = "reserved",
         [5] = "broadcast server",
         [3] = "client"
      }

   The descriptions of the NTP mode value, as described
   in :rfc:`5905`, Figure 1


