:tocdepth: 3

policy/protocols/smtp/entities-excerpt.zeek
===========================================
.. zeek:namespace:: SMTP

This script is for optionally adding a body excerpt to the SMTP
entities log.

:Namespace: SMTP
:Imports: :doc:`base/protocols/smtp/entities.zeek </scripts/base/protocols/smtp/entities.zeek>`

Summary
~~~~~~~
Runtime Options
###############
=================================================================================== ===================================================================
:zeek:id:`SMTP::default_entity_excerpt_len`: :zeek:type:`count` :zeek:attr:`&redef` This is the default value for how much of the entity body should be
                                                                                    included for all MIME entities.
=================================================================================== ===================================================================

Redefinitions
#############
============================================== ======================================================================================================
:zeek:type:`SMTP::Entity`: :zeek:type:`record` 
                                               
                                               :New Fields: :zeek:type:`SMTP::Entity`
                                               
                                                 excerpt: :zeek:type:`string` :zeek:attr:`&log` :zeek:attr:`&default` = ``""`` :zeek:attr:`&optional`
                                                   The entity body excerpt.
============================================== ======================================================================================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Runtime Options
###############
.. zeek:id:: SMTP::default_entity_excerpt_len
   :source-code: policy/protocols/smtp/entities-excerpt.zeek 17 17

   :Type: :zeek:type:`count`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``0``

   This is the default value for how much of the entity body should be
   included for all MIME entities.  The lesser of this value and
   :zeek:see:`default_file_bof_buffer_size` will be used.


