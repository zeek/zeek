:tocdepth: 3

base/utils/email.zeek
=====================



Summary
~~~~~~~
Functions
#########
============================================================ ===========================================================================
:zeek:id:`extract_email_addrs_set`: :zeek:type:`function`    Extract mail addresses out of address specifications conforming to RFC5322.
:zeek:id:`extract_email_addrs_vec`: :zeek:type:`function`    Extract mail addresses out of address specifications conforming to RFC5322.
:zeek:id:`extract_first_email_addr`: :zeek:type:`function`   Extract the first email address from a string.
:zeek:id:`split_mime_email_addresses`: :zeek:type:`function` Split email addresses from MIME headers.
============================================================ ===========================================================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Functions
#########
.. zeek:id:: extract_email_addrs_set

   :Type: :zeek:type:`function` (str: :zeek:type:`string`) : :zeek:type:`set` [:zeek:type:`string`]

   Extract mail addresses out of address specifications conforming to RFC5322.
   

   :str: A string potentially containing email addresses.
   

   :returns: A set of extracted email addresses.  An empty set is returned 
            if no email addresses are discovered.

.. zeek:id:: extract_email_addrs_vec

   :Type: :zeek:type:`function` (str: :zeek:type:`string`) : :zeek:type:`string_vec`

   Extract mail addresses out of address specifications conforming to RFC5322.
   

   :str: A string potentially containing email addresses.
   

   :returns: A vector of extracted email addresses.  An empty vector is returned
            if no email addresses are discovered.

.. zeek:id:: extract_first_email_addr

   :Type: :zeek:type:`function` (str: :zeek:type:`string`) : :zeek:type:`string`

   Extract the first email address from a string.
   

   :str: A string potentially containing email addresses.
   

   :returns: An email address or empty string if none found.

.. zeek:id:: split_mime_email_addresses

   :Type: :zeek:type:`function` (line: :zeek:type:`string`) : :zeek:type:`set` [:zeek:type:`string`]

   Split email addresses from MIME headers.  The email addresses will
   include the display name and email address as it was given by the mail
   mail client.  Note that this currently does not account for MIME group
   addresses and won't handle them correctly.  The group name will show up
   as part of an email address.
   

   :str: The argument from a MIME header.
   

   :returns: A set of addresses or empty string if none found.


