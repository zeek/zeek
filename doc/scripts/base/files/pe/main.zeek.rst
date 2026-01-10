:tocdepth: 3

base/files/pe/main.zeek
=======================
.. zeek:namespace:: PE


:Namespace: PE
:Imports: :doc:`base/files/pe/consts.zeek </scripts/base/files/pe/consts.zeek>`

Summary
~~~~~~~
Types
#####
========================================== =
:zeek:type:`PE::Info`: :zeek:type:`record`
========================================== =

Redefinitions
#############
============================================================= ==================================================
:zeek:type:`Log::ID`: :zeek:type:`enum`

                                                              * :zeek:enum:`PE::LOG`
:zeek:type:`fa_file`: :zeek:type:`record` :zeek:attr:`&redef`

                                                              :New Fields: :zeek:type:`fa_file`

                                                                pe: :zeek:type:`PE::Info` :zeek:attr:`&optional`
============================================================= ==================================================

Events
######
========================================= ===================================
:zeek:id:`PE::log_pe`: :zeek:type:`event` Event for accessing logged records.
========================================= ===================================

Hooks
#####
======================================================= ====================================================
:zeek:id:`PE::log_policy`: :zeek:type:`Log::PolicyHook`
:zeek:id:`PE::set_file`: :zeek:type:`hook`              A hook that gets called when we first see a PE file.
======================================================= ====================================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Types
#####
.. zeek:type:: PE::Info
   :source-code: base/files/pe/main.zeek 10 45

   :Type: :zeek:type:`record`


   .. zeek:field:: ts :zeek:type:`time` :zeek:attr:`&log`

      Current timestamp.


   .. zeek:field:: id :zeek:type:`string` :zeek:attr:`&log`

      File id of this portable executable file.


   .. zeek:field:: machine :zeek:type:`string` :zeek:attr:`&log` :zeek:attr:`&optional`

      The target machine that the file was compiled for.


   .. zeek:field:: compile_ts :zeek:type:`time` :zeek:attr:`&log` :zeek:attr:`&optional`

      The time that the file was created at.


   .. zeek:field:: os :zeek:type:`string` :zeek:attr:`&log` :zeek:attr:`&optional`

      The required operating system.


   .. zeek:field:: subsystem :zeek:type:`string` :zeek:attr:`&log` :zeek:attr:`&optional`

      The subsystem that is required to run this file.


   .. zeek:field:: is_exe :zeek:type:`bool` :zeek:attr:`&log` :zeek:attr:`&default` = ``T`` :zeek:attr:`&optional`

      Is the file an executable, or just an object file?


   .. zeek:field:: is_64bit :zeek:type:`bool` :zeek:attr:`&log` :zeek:attr:`&default` = ``T`` :zeek:attr:`&optional`

      Is the file a 64-bit executable?


   .. zeek:field:: uses_aslr :zeek:type:`bool` :zeek:attr:`&log` :zeek:attr:`&default` = ``F`` :zeek:attr:`&optional`

      Does the file support Address Space Layout Randomization?


   .. zeek:field:: uses_dep :zeek:type:`bool` :zeek:attr:`&log` :zeek:attr:`&default` = ``F`` :zeek:attr:`&optional`

      Does the file support Data Execution Prevention?


   .. zeek:field:: uses_code_integrity :zeek:type:`bool` :zeek:attr:`&log` :zeek:attr:`&default` = ``F`` :zeek:attr:`&optional`

      Does the file enforce code integrity checks?


   .. zeek:field:: uses_seh :zeek:type:`bool` :zeek:attr:`&log` :zeek:attr:`&default` = ``T`` :zeek:attr:`&optional`

      Does the file use structured exception handing?


   .. zeek:field:: has_import_table :zeek:type:`bool` :zeek:attr:`&log` :zeek:attr:`&optional`

      Does the file have an import table?


   .. zeek:field:: has_export_table :zeek:type:`bool` :zeek:attr:`&log` :zeek:attr:`&optional`

      Does the file have an export table?


   .. zeek:field:: has_cert_table :zeek:type:`bool` :zeek:attr:`&log` :zeek:attr:`&optional`

      Does the file have an attribute certificate table?


   .. zeek:field:: has_debug_data :zeek:type:`bool` :zeek:attr:`&log` :zeek:attr:`&optional`

      Does the file have a debug table?


   .. zeek:field:: section_names :zeek:type:`vector` of :zeek:type:`string` :zeek:attr:`&log` :zeek:attr:`&optional`

      The names of the sections, in order.



Events
######
.. zeek:id:: PE::log_pe
   :source-code: base/files/pe/main.zeek 48 48

   :Type: :zeek:type:`event` (rec: :zeek:type:`PE::Info`)

   Event for accessing logged records.

Hooks
#####
.. zeek:id:: PE::log_policy
   :source-code: base/files/pe/main.zeek 8 8

   :Type: :zeek:type:`Log::PolicyHook`


.. zeek:id:: PE::set_file
   :source-code: base/files/pe/main.zeek 66 70

   :Type: :zeek:type:`hook` (f: :zeek:type:`fa_file`) : :zeek:type:`bool`

   A hook that gets called when we first see a PE file.


