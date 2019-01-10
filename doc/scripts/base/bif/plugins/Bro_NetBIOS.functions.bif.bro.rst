:tocdepth: 3

base/bif/plugins/Bro_NetBIOS.functions.bif.bro
==============================================
.. bro:namespace:: GLOBAL


:Namespace: GLOBAL

Summary
~~~~~~~
Functions
#########
======================================================== ================================================================
:bro:id:`decode_netbios_name`: :bro:type:`function`      Decode a NetBIOS name.
:bro:id:`decode_netbios_name_type`: :bro:type:`function` Converts a NetBIOS name type to its corresponding numeric value.
======================================================== ================================================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Functions
#########
.. bro:id:: decode_netbios_name

   :Type: :bro:type:`function` (name: :bro:type:`string`) : :bro:type:`string`

   Decode a NetBIOS name.  See http://support.microsoft.com/kb/194203.
   

   :name: The encoded NetBIOS name, e.g., ``"FEEIEFCAEOEFFEECEJEPFDCAEOEBENEF"``.
   

   :returns: The decoded NetBIOS name, e.g., ``"THE NETBIOS NAME"``.
   
   .. bro:see:: decode_netbios_name_type

.. bro:id:: decode_netbios_name_type

   :Type: :bro:type:`function` (name: :bro:type:`string`) : :bro:type:`count`

   Converts a NetBIOS name type to its corresponding numeric value.
   See http://support.microsoft.com/kb/163409.
   

   :name: The NetBIOS name type.
   

   :returns: The numeric value of *name*.
   
   .. bro:see:: decode_netbios_name


