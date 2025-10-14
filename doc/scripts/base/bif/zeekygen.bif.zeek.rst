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
=================================================================== =============================================================================
:zeek:id:`get_identifier_comments`: :zeek:type:`function`           Retrieve the Zeekygen-style comments (``##``) associated with an identifier
                                                                    (e.g.
:zeek:id:`get_identifier_declaring_script`: :zeek:type:`function`   Retrieve the declaring script associated with an identifier
                                                                    (e.g.
:zeek:id:`get_package_readme`: :zeek:type:`function`                Retrieve the contents of a Zeek script package's README file.
:zeek:id:`get_record_field_comments`: :zeek:type:`function`         Retrieve the Zeekygen-style comments (``##``) associated with a record field.
:zeek:id:`get_record_field_declaring_script`: :zeek:type:`function` Retrieve the declaring script associated with a record field.
:zeek:id:`get_script_comments`: :zeek:type:`function`               Retrieve the Zeekygen-style summary comments (``##!``) associated with
                                                                    a Zeek script.
=================================================================== =============================================================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Functions
#########
.. zeek:id:: get_identifier_comments
   :source-code: base/bif/zeekygen.bif.zeek 17 17

   :Type: :zeek:type:`function` (name: :zeek:type:`string`) : :zeek:type:`string`

   Retrieve the Zeekygen-style comments (``##``) associated with an identifier
   (e.g. a variable or type).
   

   :param name: a script-level identifier for which to retrieve comments.
   

   :returns: comments associated with *name*.  If *name* is not a known
            script-level identifier, an empty string is returned.

.. zeek:id:: get_identifier_declaring_script
   :source-code: base/bif/zeekygen.bif.zeek 29 29

   :Type: :zeek:type:`function` (name: :zeek:type:`string`) : :zeek:type:`string`

   Retrieve the declaring script associated with an identifier
   (e.g. a variable or type).
   

   :param name: a script-level identifier
   

   :returns: declaring script associated with *name*. If *name* is not a known
            script-level identifier, an empty string is returned.
   
   .. zeek:see:: get_record_field_declaring_script

.. zeek:id:: get_package_readme
   :source-code: base/bif/zeekygen.bif.zeek 51 51

   :Type: :zeek:type:`function` (name: :zeek:type:`string`) : :zeek:type:`string`

   Retrieve the contents of a Zeek script package's README file.
   

   :param name: the name of a Zeek script package.  It must be a relative path
         to where it is located within a particular component of ZEEKPATH.
   

   :returns: contents of the package's README file.  If *name* is not a known
            package, an empty string is returned.

.. zeek:id:: get_record_field_comments
   :source-code: base/bif/zeekygen.bif.zeek 62 62

   :Type: :zeek:type:`function` (name: :zeek:type:`string`) : :zeek:type:`string`

   Retrieve the Zeekygen-style comments (``##``) associated with a record field.
   

   :param name: the name of a script-level record type and a field within it formatted
         like a typical record field access: "<record_type>$<field>".
   

   :returns: comments associated with the record field.  If *name* does
            not point to a known script-level record type or a known field within
            a record type, an empty string is returned.

.. zeek:id:: get_record_field_declaring_script
   :source-code: base/bif/zeekygen.bif.zeek 78 78

   :Type: :zeek:type:`function` (name: :zeek:type:`string`) : :zeek:type:`string`

   Retrieve the declaring script associated with a record field.
   
   The declaring script for a field is different from the declaring script
   of the record type itself when fields were added via redef.
   

   :param name: the name of a script-level record type and a field within it formatted
         like a typical record field access: "<record_type>$<field>".
   

   :returns: the declaring script associated with the record field.  If *name* does
            not point to a known script-level record type or a known field within
            a record type, an empty string is returned.
   
   .. zeek:see:: get_identifier_declaring_script

.. zeek:id:: get_script_comments
   :source-code: base/bif/zeekygen.bif.zeek 41 41

   :Type: :zeek:type:`function` (name: :zeek:type:`string`) : :zeek:type:`string`

   Retrieve the Zeekygen-style summary comments (``##!``) associated with
   a Zeek script.
   

   :param name: the name of a Zeek script.  It must be a relative path to where
         it is located within a particular component of ZEEKPATH and use
         the same file name extension/suffix as the actual file (e.g. ".zeek").
   

   :returns: summary comments associated with script with *name*.  If
            *name* is not a known script, an empty string is returned.


