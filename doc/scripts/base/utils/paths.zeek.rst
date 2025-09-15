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
:zeek:id:`extract_path`: :zeek:type:`function`          Given an arbitrary string, extracts a single, absolute path (directory
                                                        with filename).
======================================================= ======================================================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Constants
#########
.. zeek:id:: absolute_path_pat
   :source-code: base/utils/paths.zeek 3 3

   :Type: :zeek:type:`pattern`
   :Default:

      ::

         /^?((\/|[A-Za-z]:[\\\/]).*)$?/



Functions
#########
.. zeek:id:: build_path
   :source-code: base/utils/paths.zeek 32 38

   :Type: :zeek:type:`function` (dir: :zeek:type:`string`, file_name: :zeek:type:`string`) : :zeek:type:`string`

   Constructs a path to a file given a directory and a file name.
   

   :param dir: the directory in which the file lives.
   

   :param file_name: the name of the file.
   

   :returns: the concatenation of the directory path and file name, or just
            the file name if it's already an absolute path or dir is empty.

.. zeek:id:: build_path_compressed
   :source-code: base/utils/paths.zeek 42 45

   :Type: :zeek:type:`function` (dir: :zeek:type:`string`, file_name: :zeek:type:`string`) : :zeek:type:`string`

   Returns a compressed path to a file given a directory and file name.
   See :zeek:id:`build_path` and :zeek:id:`compress_path`.

.. zeek:id:: extract_path
   :source-code: base/utils/paths.zeek 13 22

   :Type: :zeek:type:`function` (input: :zeek:type:`string`) : :zeek:type:`string`

   Given an arbitrary string, extracts a single, absolute path (directory
   with filename).
   
   .. todo:: Make this work on Window's style directories.
   

   :param input: a string that may contain an absolute path.
   

   :returns: the first absolute path found in input string, else an empty string.


