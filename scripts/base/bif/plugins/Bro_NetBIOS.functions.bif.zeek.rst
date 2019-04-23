:tocdepth: 3

base/bif/plugins/Bro_NetBIOS.functions.bif.zeek
===============================================
.. zeek:namespace:: GLOBAL


:Namespace: GLOBAL

Summary
~~~~~~~
Functions
#########
========================================================== ================================================================
:zeek:id:`decode_netbios_name`: :zeek:type:`function`      Decode a NetBIOS name.
:zeek:id:`decode_netbios_name_type`: :zeek:type:`function` Converts a NetBIOS name type to its corresponding numeric value.
========================================================== ================================================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Functions
#########
.. zeek:id:: decode_netbios_name

   :Type: :zeek:type:`function` (name: :zeek:type:`string`) : :zeek:type:`string`

   Decode a NetBIOS name.  See http://support.microsoft.com/kb/194203.
   

   :name: The encoded NetBIOS name, e.g., ``"FEEIEFCAEOEFFEECEJEPFDCAEOEBENEF"``.
   

   :returns: The decoded NetBIOS name, e.g., ``"THE NETBIOS NAME"``.
   
   .. zeek:see:: decode_netbios_name_type

.. zeek:id:: decode_netbios_name_type

   :Type: :zeek:type:`function` (name: :zeek:type:`string`) : :zeek:type:`count`

   Converts a NetBIOS name type to its corresponding numeric value.
   See http://support.microsoft.com/kb/163409.
   

   :name: The NetBIOS name type.
   

   :returns: The numeric value of *name*.
   
   .. zeek:see:: decode_netbios_name


