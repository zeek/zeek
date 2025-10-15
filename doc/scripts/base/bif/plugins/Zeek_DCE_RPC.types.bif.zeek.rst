:tocdepth: 3

base/bif/plugins/Zeek_DCE_RPC.types.bif.zeek
============================================
.. zeek:namespace:: DCE_RPC
.. zeek:namespace:: GLOBAL


:Namespaces: DCE_RPC, GLOBAL

Summary
~~~~~~~
Types
#####
============================================== =
:zeek:type:`DCE_RPC::IfID`: :zeek:type:`enum`  
:zeek:type:`DCE_RPC::PType`: :zeek:type:`enum` 
============================================== =


Detailed Interface
~~~~~~~~~~~~~~~~~~
Types
#####
.. zeek:type:: DCE_RPC::IfID
   :source-code: base/bif/plugins/Zeek_DCE_RPC.types.bif.zeek 33 33

   :Type: :zeek:type:`enum`

      .. zeek:enum:: DCE_RPC::unknown_if DCE_RPC::IfID

      .. zeek:enum:: DCE_RPC::epmapper DCE_RPC::IfID

      .. zeek:enum:: DCE_RPC::lsarpc DCE_RPC::IfID

      .. zeek:enum:: DCE_RPC::lsa_ds DCE_RPC::IfID

      .. zeek:enum:: DCE_RPC::mgmt DCE_RPC::IfID

      .. zeek:enum:: DCE_RPC::netlogon DCE_RPC::IfID

      .. zeek:enum:: DCE_RPC::samr DCE_RPC::IfID

      .. zeek:enum:: DCE_RPC::srvsvc DCE_RPC::IfID

      .. zeek:enum:: DCE_RPC::spoolss DCE_RPC::IfID

      .. zeek:enum:: DCE_RPC::drs DCE_RPC::IfID

      .. zeek:enum:: DCE_RPC::winspipe DCE_RPC::IfID

      .. zeek:enum:: DCE_RPC::wkssvc DCE_RPC::IfID

      .. zeek:enum:: DCE_RPC::oxid DCE_RPC::IfID

      .. zeek:enum:: DCE_RPC::ISCMActivator DCE_RPC::IfID


.. zeek:type:: DCE_RPC::PType
   :source-code: base/bif/plugins/Zeek_DCE_RPC.types.bif.zeek 8 8

   :Type: :zeek:type:`enum`

      .. zeek:enum:: DCE_RPC::REQUEST DCE_RPC::PType

      .. zeek:enum:: DCE_RPC::PING DCE_RPC::PType

      .. zeek:enum:: DCE_RPC::RESPONSE DCE_RPC::PType

      .. zeek:enum:: DCE_RPC::FAULT DCE_RPC::PType

      .. zeek:enum:: DCE_RPC::WORKING DCE_RPC::PType

      .. zeek:enum:: DCE_RPC::NOCALL DCE_RPC::PType

      .. zeek:enum:: DCE_RPC::REJECT DCE_RPC::PType

      .. zeek:enum:: DCE_RPC::ACK DCE_RPC::PType

      .. zeek:enum:: DCE_RPC::CL_CANCEL DCE_RPC::PType

      .. zeek:enum:: DCE_RPC::FACK DCE_RPC::PType

      .. zeek:enum:: DCE_RPC::CANCEL_ACK DCE_RPC::PType

      .. zeek:enum:: DCE_RPC::BIND DCE_RPC::PType

      .. zeek:enum:: DCE_RPC::BIND_ACK DCE_RPC::PType

      .. zeek:enum:: DCE_RPC::BIND_NAK DCE_RPC::PType

      .. zeek:enum:: DCE_RPC::ALTER_CONTEXT DCE_RPC::PType

      .. zeek:enum:: DCE_RPC::ALTER_CONTEXT_RESP DCE_RPC::PType

      .. zeek:enum:: DCE_RPC::AUTH3 DCE_RPC::PType

      .. zeek:enum:: DCE_RPC::SHUTDOWN DCE_RPC::PType

      .. zeek:enum:: DCE_RPC::CO_CANCEL DCE_RPC::PType

      .. zeek:enum:: DCE_RPC::ORPHANED DCE_RPC::PType

      .. zeek:enum:: DCE_RPC::RTS DCE_RPC::PType



