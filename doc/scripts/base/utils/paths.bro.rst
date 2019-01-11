:tocdepth: 3

base/utils/paths.bro
====================

Functions to parse and manipulate UNIX style paths and directories.


Summary
~~~~~~~
Constants
#########
================================================ =
:bro:id:`absolute_path_pat`: :bro:type:`pattern` 
================================================ =

Functions
#########
===================================================== ======================================================================
:bro:id:`build_path`: :bro:type:`function`            Constructs a path to a file given a directory and a file name.
:bro:id:`build_path_compressed`: :bro:type:`function` Returns a compressed path to a file given a directory and file name.
:bro:id:`compress_path`: :bro:type:`function`         Compresses a given path by removing '..'s and the parent directory it
                                                      references and also removing dual '/'s and extraneous '/./'s.
:bro:id:`extract_path`: :bro:type:`function`          Given an arbitrary string, extracts a single, absolute path (directory
                                                      with filename).
===================================================== ======================================================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Constants
#########
.. bro:id:: absolute_path_pat

   :Type: :bro:type:`pattern`
   :Default:

   ::

      /^?((\/|[A-Za-z]:[\\\/]).*)$?/


Functions
#########
.. bro:id:: build_path

   :Type: :bro:type:`function` (dir: :bro:type:`string`, file_name: :bro:type:`string`) : :bro:type:`string`

   Constructs a path to a file given a directory and a file name.
   

   :dir: the directory in which the file lives.
   

   :file_name: the name of the file.
   

   :returns: the concatenation of the directory path and file name, or just
            the file name if it's already an absolute path.

.. bro:id:: build_path_compressed

   :Type: :bro:type:`function` (dir: :bro:type:`string`, file_name: :bro:type:`string`) : :bro:type:`string`

   Returns a compressed path to a file given a directory and file name.
   See :bro:id:`build_path` and :bro:id:`compress_path`.

.. bro:id:: compress_path

   :Type: :bro:type:`function` (dir: :bro:type:`string`) : :bro:type:`string`

   Compresses a given path by removing '..'s and the parent directory it
   references and also removing dual '/'s and extraneous '/./'s.
   

   :dir: a path string, either relative or absolute.
   

   :returns: a compressed version of the input path.

.. bro:id:: extract_path

   :Type: :bro:type:`function` (input: :bro:type:`string`) : :bro:type:`string`

   Given an arbitrary string, extracts a single, absolute path (directory
   with filename).
   
   .. todo:: Make this work on Window's style directories.
   

   :input: a string that may contain an absolute path.
   

   :returns: the first absolute path found in input string, else an empty string.


