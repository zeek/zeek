:tocdepth: 3

base/bif/broxygen.bif.bro
=========================
.. bro:namespace:: GLOBAL

Functions for querying script, package, or variable documentation.

:Namespace: GLOBAL

Summary
~~~~~~~
Functions
#########
========================================================= =============================================================================
:bro:id:`get_identifier_comments`: :bro:type:`function`   Retrieve the Broxygen-style comments (``##``) associated with an identifier
                                                          (e.g.
:bro:id:`get_package_readme`: :bro:type:`function`        Retrieve the contents of a Bro script package's README file.
:bro:id:`get_record_field_comments`: :bro:type:`function` Retrieve the Broxygen-style comments (``##``) associated with a record field.
:bro:id:`get_script_comments`: :bro:type:`function`       Retrieve the Broxygen-style summary comments (``##!``) associated with
                                                          a Bro script.
========================================================= =============================================================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Functions
#########
.. bro:id:: get_identifier_comments

   :Type: :bro:type:`function` (name: :bro:type:`string`) : :bro:type:`string`

   Retrieve the Broxygen-style comments (``##``) associated with an identifier
   (e.g. a variable or type).
   

   :name: a script-level identifier for which to retrieve comments.
   

   :returns: comments associated with *name*.  If *name* is not a known
            identifier, an empty string is returned.

.. bro:id:: get_package_readme

   :Type: :bro:type:`function` (name: :bro:type:`string`) : :bro:type:`string`

   Retrieve the contents of a Bro script package's README file.
   

   :name: the name of a Bro script package.  It must be a relative path
         to where it is located within a particular component of BROPATH.
   

   :returns: contents of the package's README file.  If *name* is not a known
            package, an empty string is returned.

.. bro:id:: get_record_field_comments

   :Type: :bro:type:`function` (name: :bro:type:`string`) : :bro:type:`string`

   Retrieve the Broxygen-style comments (``##``) associated with a record field.
   

   :name: the name of a record type and a field within it formatted like
         a typical record field access: "<record_type>$<field>".
   

   :returns: comments associated with the record field.  If *name* does
            not point to a known record type or a known field within a record
            type, an empty string is returned.

.. bro:id:: get_script_comments

   :Type: :bro:type:`function` (name: :bro:type:`string`) : :bro:type:`string`

   Retrieve the Broxygen-style summary comments (``##!``) associated with
   a Bro script.
   

   :name: the name of a Bro script.  It must be a relative path to where
         it is located within a particular component of BROPATH and use
         the same file name extension/suffix as the actual file (e.g. ".bro").
   

   :returns: summary comments associated with script with *name*.  If
            *name* is not a known script, an empty string is returned.


