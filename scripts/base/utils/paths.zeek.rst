:tocdepth: 3

base/utils/paths.zeek
=====================

Functions to parse and manipulate UNIX style paths and directories.


Summary
~~~~~~~
Constants
#########
================================================== =
:zeek:id:`absolute_path_pat`: :zeek:type:`pattern` 
================================================== =

Functions
#########
======================================================= ======================================================================
:zeek:id:`build_path`: :zeek:type:`function`            Constructs a path to a file given a directory and a file name.
:zeek:id:`build_path_compressed`: :zeek:type:`function` Returns a compressed path to a file given a directory and file name.
:zeek:id:`compress_path`: :zeek:type:`function`         Compresses a given path by removing '..'s and the parent directory it
                                                        references and also removing dual '/'s and extraneous '/./'s.
:zeek:id:`extract_path`: :zeek:type:`function`          Given an arbitrary string, extracts a single, absolute path (directory
                                                        with filename).
======================================================= ======================================================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Constants
#########
.. zeek:id:: absolute_path_pat

   :Type: :zeek:type:`pattern`
   :Default:

   ::

      /^?((\/|[A-Za-z]:[\\\/]).*)$?/


Functions
#########
.. zeek:id:: build_path

   :Type: :zeek:type:`function` (dir: :zeek:type:`string`, file_name: :zeek:type:`string`) : :zeek:type:`string`

   Constructs a path to a file given a directory and a file name.
   

   :dir: the directory in which the file lives.
   

   :file_name: the name of the file.
   

   :returns: the concatenation of the directory path and file name, or just
            the file name if it's already an absolute path.

.. zeek:id:: build_path_compressed

   :Type: :zeek:type:`function` (dir: :zeek:type:`string`, file_name: :zeek:type:`string`) : :zeek:type:`string`

   Returns a compressed path to a file given a directory and file name.
   See :zeek:id:`build_path` and :zeek:id:`compress_path`.

.. zeek:id:: compress_path

   :Type: :zeek:type:`function` (dir: :zeek:type:`string`) : :zeek:type:`string`

   Compresses a given path by removing '..'s and the parent directory it
   references and also removing dual '/'s and extraneous '/./'s.
   

   :dir: a path string, either relative or absolute.
   

   :returns: a compressed version of the input path.

.. zeek:id:: extract_path

   :Type: :zeek:type:`function` (input: :zeek:type:`string`) : :zeek:type:`string`

   Given an arbitrary string, extracts a single, absolute path (directory
   with filename).
   
   .. todo:: Make this work on Window's style directories.
   

   :input: a string that may contain an absolute path.
   

   :returns: the first absolute path found in input string, else an empty string.


