:tocdepth: 3

base/protocols/quic/consts.zeek
===============================
.. zeek:namespace:: QUIC


:Namespace: QUIC

Summary
~~~~~~~
Constants
#########
================================================================================================== =
:zeek:id:`QUIC::version_strings`: :zeek:type:`table` :zeek:attr:`&default` = :zeek:type:`function` 
================================================================================================== =


Detailed Interface
~~~~~~~~~~~~~~~~~~
Constants
#########
.. zeek:id:: QUIC::version_strings
   :source-code: base/protocols/quic/consts.zeek 4 4

   :Type: :zeek:type:`table` [:zeek:type:`count`] of :zeek:type:`string`
   :Attributes: :zeek:attr:`&default` = :zeek:type:`function`
   :Default:

      ::

         {
            [4207849486] = "mvfst (faceb00e)",
            [4278190112] = "draft-32",
            [4278190110] = "draft-30",
            [4278190111] = "draft-30",
            [4278190114] = "draft-34",
            [4207849474] = "mvfst (faceb002)",
            [4278190108] = "draft-28",
            [4278190113] = "draft-33",
            [4278190104] = "draft-24",
            [4278190105] = "draft-25",
            [1] = "1",
            [1798521807] = "quicv2",
            [4207849491] = "mvfst (faceb013)",
            [4207849489] = "mvfst (faceb011)",
            [4278190106] = "draft-26",
            [4207849490] = "mvfst (faceb012)",
            [4278190107] = "draft-27",
            [4278190103] = "draft-23",
            [4278190102] = "draft-22",
            [4278190109] = "draft-29",
            [4207849473] = "mvfst (faceb001)"
         }




