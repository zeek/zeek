:tocdepth: 3

base/utils/exec.zeek
====================
.. zeek:namespace:: Exec

A module for executing external command line programs.

:Namespace: Exec
:Imports: :doc:`base/frameworks/input </scripts/base/frameworks/input/index>`

Summary
~~~~~~~
Types
#####
=============================================== =
:zeek:type:`Exec::Command`: :zeek:type:`record` 
:zeek:type:`Exec::Result`: :zeek:type:`record`  
=============================================== =

Functions
#########
=========================================== ======================================================
:zeek:id:`Exec::run`: :zeek:type:`function` Function for running command line programs and getting
                                            output.
=========================================== ======================================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Types
#####
.. zeek:type:: Exec::Command
   :source-code: base/utils/exec.zeek 8 20

   :Type: :zeek:type:`record`


   .. zeek:field:: cmd :zeek:type:`string`

      The command line to execute. Use care to avoid injection
      attacks (i.e., if the command uses untrusted/variable data,
      sanitize it with :zeek:see:`safe_shell_quote`).


   .. zeek:field:: stdin :zeek:type:`string` :zeek:attr:`&default` = ``""`` :zeek:attr:`&optional`

      Provide standard input to the program as a string.


   .. zeek:field:: read_files :zeek:type:`set` [:zeek:type:`string`] :zeek:attr:`&optional`

      If additional files are required to be read in as part of the
      output of the command they can be defined here.


   .. zeek:field:: uid :zeek:type:`string` :zeek:attr:`&default` = ``Chd8EgFWk2j`` :zeek:attr:`&optional`

      The unique id for tracking executors.



.. zeek:type:: Exec::Result
   :source-code: base/utils/exec.zeek 22 34

   :Type: :zeek:type:`record`


   .. zeek:field:: exit_code :zeek:type:`count` :zeek:attr:`&default` = ``0`` :zeek:attr:`&optional`

      Exit code from the program.


   .. zeek:field:: signal_exit :zeek:type:`bool` :zeek:attr:`&default` = ``F`` :zeek:attr:`&optional`

      True if the command was terminated with a signal.


   .. zeek:field:: stdout :zeek:type:`vector` of :zeek:type:`string` :zeek:attr:`&optional`

      Each line of standard output.


   .. zeek:field:: stderr :zeek:type:`vector` of :zeek:type:`string` :zeek:attr:`&optional`

      Each line of standard error.


   .. zeek:field:: files :zeek:type:`table` [:zeek:type:`string`] of :zeek:type:`string_vec` :zeek:attr:`&optional`

      If additional files were requested to be read in
      the content of the files will be available here.



Functions
#########
.. zeek:id:: Exec::run
   :source-code: base/utils/exec.zeek 153 187

   :Type: :zeek:type:`function` (cmd: :zeek:type:`Exec::Command`) : :zeek:type:`Exec::Result`

   Function for running command line programs and getting
   output. This is an asynchronous function which is meant
   to be run with the ``when`` statement.
   

   :param cmd: The command to run. Use care to avoid injection attacks!
   

   :returns: A record representing the full results from the
            external program execution.


