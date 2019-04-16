:tocdepth: 3

policy/protocols/smtp/entities-excerpt.zeek
===========================================
.. bro:namespace:: SMTP

This script is for optionally adding a body excerpt to the SMTP
entities log.

:Namespace: SMTP
:Imports: :doc:`base/protocols/smtp/entities.zeek </scripts/base/protocols/smtp/entities.zeek>`

Summary
~~~~~~~
Runtime Options
###############
================================================================================ ===================================================================
:bro:id:`SMTP::default_entity_excerpt_len`: :bro:type:`count` :bro:attr:`&redef` This is the default value for how much of the entity body should be
                                                                                 included for all MIME entities.
================================================================================ ===================================================================

Redefinitions
#############
============================================ =
:bro:type:`SMTP::Entity`: :bro:type:`record` 
============================================ =


Detailed Interface
~~~~~~~~~~~~~~~~~~
Runtime Options
###############
.. bro:id:: SMTP::default_entity_excerpt_len

   :Type: :bro:type:`count`
   :Attributes: :bro:attr:`&redef`
   :Default: ``0``

   This is the default value for how much of the entity body should be
   included for all MIME entities.  The lesser of this value and
   :bro:see:`default_file_bof_buffer_size` will be used.


