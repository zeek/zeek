:tocdepth: 3

base/utils/exec.zeek
====================
.. bro:namespace:: Exec

A module for executing external command line programs.

:Namespace: Exec
:Imports: :doc:`base/frameworks/input </scripts/base/frameworks/input/index>`

Summary
~~~~~~~
Types
#####
============================================= =
:bro:type:`Exec::Command`: :bro:type:`record` 
:bro:type:`Exec::Result`: :bro:type:`record`  
============================================= =

Functions
#########
========================================= ======================================================
:bro:id:`Exec::run`: :bro:type:`function` Function for running command line programs and getting
                                          output.
========================================= ======================================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Types
#####
.. bro:type:: Exec::Command

   :Type: :bro:type:`record`

      cmd: :bro:type:`string`
         The command line to execute.  Use care to avoid injection
         attacks (i.e., if the command uses untrusted/variable data,
         sanitize it with :bro:see:`safe_shell_quote`).

      stdin: :bro:type:`string` :bro:attr:`&default` = ``""`` :bro:attr:`&optional`
         Provide standard input to the program as a string.

      read_files: :bro:type:`set` [:bro:type:`string`] :bro:attr:`&optional`
         If additional files are required to be read in as part of the
         output of the command they can be defined here.

      uid: :bro:type:`string` :bro:attr:`&default` = ``rFj3eGxkRR5`` :bro:attr:`&optional`
         The unique id for tracking executors.


.. bro:type:: Exec::Result

   :Type: :bro:type:`record`

      exit_code: :bro:type:`count` :bro:attr:`&default` = ``0`` :bro:attr:`&optional`
         Exit code from the program.

      signal_exit: :bro:type:`bool` :bro:attr:`&default` = ``F`` :bro:attr:`&optional`
         True if the command was terminated with a signal.

      stdout: :bro:type:`vector` of :bro:type:`string` :bro:attr:`&optional`
         Each line of standard output.

      stderr: :bro:type:`vector` of :bro:type:`string` :bro:attr:`&optional`
         Each line of standard error.

      files: :bro:type:`table` [:bro:type:`string`] of :bro:type:`string_vec` :bro:attr:`&optional`
         If additional files were requested to be read in
         the content of the files will be available here.


Functions
#########
.. bro:id:: Exec::run

   :Type: :bro:type:`function` (cmd: :bro:type:`Exec::Command`) : :bro:type:`Exec::Result`

   Function for running command line programs and getting
   output.  This is an asynchronous function which is meant
   to be run with the `when` statement.
   

   :cmd: The command to run.  Use care to avoid injection attacks!
   

   :returns: A record representing the full results from the
            external program execution.


