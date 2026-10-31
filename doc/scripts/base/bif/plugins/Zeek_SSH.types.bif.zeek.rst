:tocdepth: 3

base/bif/plugins/Zeek_SSH.types.bif.zeek
========================================
.. zeek:namespace:: GLOBAL
.. zeek:namespace:: SSH


:Namespaces: GLOBAL, SSH

Summary
~~~~~~~
Types
#####
============================================== ==========================================================================
:zeek:type:`SSH::KexMethod`: :zeek:type:`enum` Families of SSH key exchange methods, which determine how the SSH analyzer
                                               parses key exchange messages.
============================================== ==========================================================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Types
#####
.. zeek:type:: SSH::KexMethod
   :source-code: base/bif/plugins/Zeek_SSH.types.bif.zeek 14 14

   :Type: :zeek:type:`enum`

      .. zeek:enum:: SSH::KEX_DH SSH::KexMethod

      .. zeek:enum:: SSH::KEX_DH_GEX SSH::KexMethod

      .. zeek:enum:: SSH::KEX_ECC SSH::KexMethod

      .. zeek:enum:: SSH::KEX_GSS SSH::KexMethod

      .. zeek:enum:: SSH::KEX_RSA SSH::KexMethod

   Families of SSH key exchange methods, which determine how the SSH analyzer
   parses key exchange messages.

   .. zeek:see:: SSH::kex_methods


