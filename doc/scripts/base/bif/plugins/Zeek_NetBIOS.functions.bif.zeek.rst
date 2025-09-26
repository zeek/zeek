:tocdepth: 3

base/bif/plugins/Zeek_NetBIOS.functions.bif.zeek
================================================
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
   :source-code: base/bif/plugins/Zeek_NetBIOS.functions.bif.zeek 16 16

   :Type: :zeek:type:`function` (name: :zeek:type:`string`) : :zeek:type:`string`

   Decode a NetBIOS name.  See https://jeffpar.github.io/kbarchive/kb/194/Q194203/.
   

   :param name: The encoded NetBIOS name, e.g., ``"FEEIEFCAEOEFFEECEJEPFDCAEOEBENEF"``.
   

   :returns: The decoded NetBIOS name, e.g., ``"THE NETBIOS NAM"``.  An empty
            string is returned if the argument is not a valid NetBIOS encoding
            (though an encoding that would decode to something that includes
            only null-bytes or space-characters also yields an empty string).
   
   .. zeek:see:: decode_netbios_name_type

.. zeek:id:: decode_netbios_name_type
   :source-code: base/bif/plugins/Zeek_NetBIOS.functions.bif.zeek 27 27

   :Type: :zeek:type:`function` (name: :zeek:type:`string`) : :zeek:type:`count`

   Converts a NetBIOS name type to its corresponding numeric value.
   See https://en.wikipedia.org/wiki/NetBIOS#NetBIOS_Suffixes.
   

   :param name: An encoded NetBIOS name.
   

   :returns: The numeric value of *name* or 256 if it's not a valid encoding.
   
   .. zeek:see:: decode_netbios_name


