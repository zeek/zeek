:tocdepth: 3

base/bif/zeekygen.bif.zeek
==========================
.. zeek:namespace:: GLOBAL

Functions for querying script, package, or variable documentation.

:Namespace: GLOBAL

Summary
~~~~~~~
Functions
#########
=========================================================== =============================================================================
:zeek:id:`get_identifier_comments`: :zeek:type:`function`   Retrieve the Zeekygen-style comments (``##``) associated with an identifier
                                                            (e.g.
:zeek:id:`get_package_readme`: :zeek:type:`function`        Retrieve the contents of a Bro script package's README file.
:zeek:id:`get_record_field_comments`: :zeek:type:`function` Retrieve the Zeekygen-style comments (``##``) associated with a record field.
:zeek:id:`get_script_comments`: :zeek:type:`function`       Retrieve the Zeekygen-style summary comments (``##!``) associated with
                                                            a Bro script.
=========================================================== =============================================================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Functions
#########
.. zeek:id:: get_identifier_comments

   :Type: :zeek:type:`function` (name: :zeek:type:`string`) : :zeek:type:`string`

   Retrieve the Zeekygen-style comments (``##``) associated with an identifier
   (e.g. a variable or type).
   

   :name: a script-level identifier for which to retrieve comments.
   

   :returns: comments associated with *name*.  If *name* is not a known
            identifier, an empty string is returned.

.. zeek:id:: get_package_readme

   :Type: :zeek:type:`function` (name: :zeek:type:`string`) : :zeek:type:`string`

   Retrieve the contents of a Bro script package's README file.
   

   :name: the name of a Bro script package.  It must be a relative path
         to where it is located within a particular component of BROPATH.
   

   :returns: contents of the package's README file.  If *name* is not a known
            package, an empty string is returned.

.. zeek:id:: get_record_field_comments

   :Type: :zeek:type:`function` (name: :zeek:type:`string`) : :zeek:type:`string`

   Retrieve the Zeekygen-style comments (``##``) associated with a record field.
   

   :name: the name of a record type and a field within it formatted like
         a typical record field access: "<record_type>$<field>".
   

   :returns: comments associated with the record field.  If *name* does
            not point to a known record type or a known field within a record
            type, an empty string is returned.

.. zeek:id:: get_script_comments

   :Type: :zeek:type:`function` (name: :zeek:type:`string`) : :zeek:type:`string`

   Retrieve the Zeekygen-style summary comments (``##!``) associated with
   a Bro script.
   

   :name: the name of a Bro script.  It must be a relative path to where
         it is located within a particular component of BROPATH and use
         the same file name extension/suffix as the actual file (e.g. ".zeek").
   

   :returns: summary comments associated with script with *name*.  If
            *name* is not a known script, an empty string is returned.


