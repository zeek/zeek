:tocdepth: 3

base/protocols/postgresql/consts.zeek
=====================================
.. zeek:namespace:: PostgreSQL


:Namespace: PostgreSQL

Summary
~~~~~~~
State Variables
###############
====================================================================================================================== =
:zeek:id:`PostgreSQL::auth_ids`: :zeek:type:`table` :zeek:attr:`&default` = :zeek:type:`function` :zeek:attr:`&redef`
:zeek:id:`PostgreSQL::error_ids`: :zeek:type:`table` :zeek:attr:`&default` = :zeek:type:`function` :zeek:attr:`&redef`
====================================================================================================================== =


Detailed Interface
~~~~~~~~~~~~~~~~~~
State Variables
###############
.. zeek:id:: PostgreSQL::auth_ids
   :source-code: base/protocols/postgresql/consts.zeek 26 26

   :Type: :zeek:type:`table` [:zeek:type:`count`] of :zeek:type:`string`
   :Attributes: :zeek:attr:`&default` = :zeek:type:`function` :zeek:attr:`&redef`
   :Default:

      ::

         {
            [2] = "KerberosV5",
            [8] = "GSSAPIContinue",
            [11] = "SASLContinue",
            [3] = "CleartextPassword",
            [7] = "GSSAPI",
            [5] = "MD5Password",
            [9] = "SSPI",
            [10] = "SASL",
            [12] = "SASLFinal"
         }



.. zeek:id:: PostgreSQL::error_ids
   :source-code: base/protocols/postgresql/consts.zeek 5 5

   :Type: :zeek:type:`table` [:zeek:type:`string`] of :zeek:type:`string`
   :Attributes: :zeek:attr:`&default` = :zeek:type:`function` :zeek:attr:`&redef`
   :Default:

      ::

         {
            ["R"] = "Routine",
            ["H"] = "Hint",
            ["D"] = "Detail",
            ["S"] = "SeverityLocalized",
            ["d"] = "Data",
            ["p"] = "InternalPosition",
            ["W"] = "Where",
            ["M"] = "Message",
            ["n"] = "Constraint",
            ["c"] = "Column",
            ["V"] = "Severity",
            ["t"] = "Table",
            ["C"] = "Code",
            ["F"] = "File",
            ["P"] = "Position",
            ["s"] = "Schema",
            ["q"] = "InternalQuery",
            ["L"] = "Line"
         }




