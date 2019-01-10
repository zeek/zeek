:tocdepth: 3

base/files/pe/main.bro
======================
.. bro:namespace:: PE


:Namespace: PE
:Imports: :doc:`base/files/pe/consts.bro </scripts/base/files/pe/consts.bro>`

Summary
~~~~~~~
Types
#####
======================================== =
:bro:type:`PE::Info`: :bro:type:`record` 
======================================== =

Redefinitions
#############
========================================================== =
:bro:type:`Log::ID`: :bro:type:`enum`                      
:bro:type:`fa_file`: :bro:type:`record` :bro:attr:`&redef` 
========================================================== =

Events
######
======================================= ===================================
:bro:id:`PE::log_pe`: :bro:type:`event` Event for accessing logged records.
======================================= ===================================

Hooks
#####
======================================== ====================================================
:bro:id:`PE::set_file`: :bro:type:`hook` A hook that gets called when we first see a PE file.
======================================== ====================================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Types
#####
.. bro:type:: PE::Info

   :Type: :bro:type:`record`

      ts: :bro:type:`time` :bro:attr:`&log`
         Current timestamp.

      id: :bro:type:`string` :bro:attr:`&log`
         File id of this portable executable file.

      machine: :bro:type:`string` :bro:attr:`&log` :bro:attr:`&optional`
         The target machine that the file was compiled for.

      compile_ts: :bro:type:`time` :bro:attr:`&log` :bro:attr:`&optional`
         The time that the file was created at.

      os: :bro:type:`string` :bro:attr:`&log` :bro:attr:`&optional`
         The required operating system.

      subsystem: :bro:type:`string` :bro:attr:`&log` :bro:attr:`&optional`
         The subsystem that is required to run this file.

      is_exe: :bro:type:`bool` :bro:attr:`&log` :bro:attr:`&default` = ``T`` :bro:attr:`&optional`
         Is the file an executable, or just an object file?

      is_64bit: :bro:type:`bool` :bro:attr:`&log` :bro:attr:`&default` = ``T`` :bro:attr:`&optional`
         Is the file a 64-bit executable?

      uses_aslr: :bro:type:`bool` :bro:attr:`&log` :bro:attr:`&default` = ``F`` :bro:attr:`&optional`
         Does the file support Address Space Layout Randomization?

      uses_dep: :bro:type:`bool` :bro:attr:`&log` :bro:attr:`&default` = ``F`` :bro:attr:`&optional`
         Does the file support Data Execution Prevention?

      uses_code_integrity: :bro:type:`bool` :bro:attr:`&log` :bro:attr:`&default` = ``F`` :bro:attr:`&optional`
         Does the file enforce code integrity checks?

      uses_seh: :bro:type:`bool` :bro:attr:`&log` :bro:attr:`&default` = ``T`` :bro:attr:`&optional`
         Does the file use structured exception handing?

      has_import_table: :bro:type:`bool` :bro:attr:`&log` :bro:attr:`&optional`
         Does the file have an import table?

      has_export_table: :bro:type:`bool` :bro:attr:`&log` :bro:attr:`&optional`
         Does the file have an export table?

      has_cert_table: :bro:type:`bool` :bro:attr:`&log` :bro:attr:`&optional`
         Does the file have an attribute certificate table?

      has_debug_data: :bro:type:`bool` :bro:attr:`&log` :bro:attr:`&optional`
         Does the file have a debug table?

      section_names: :bro:type:`vector` of :bro:type:`string` :bro:attr:`&log` :bro:attr:`&optional`
         The names of the sections, in order.


Events
######
.. bro:id:: PE::log_pe

   :Type: :bro:type:`event` (rec: :bro:type:`PE::Info`)

   Event for accessing logged records.

Hooks
#####
.. bro:id:: PE::set_file

   :Type: :bro:type:`hook` (f: :bro:type:`fa_file`) : :bro:type:`bool`

   A hook that gets called when we first see a PE file.


