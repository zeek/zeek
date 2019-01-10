:tocdepth: 3

base/utils/email.bro
====================



Summary
~~~~~~~
Functions
#########
========================================================== ===========================================================================
:bro:id:`extract_email_addrs_set`: :bro:type:`function`    Extract mail addresses out of address specifications conforming to RFC5322.
:bro:id:`extract_email_addrs_vec`: :bro:type:`function`    Extract mail addresses out of address specifications conforming to RFC5322.
:bro:id:`extract_first_email_addr`: :bro:type:`function`   Extract the first email address from a string.
:bro:id:`split_mime_email_addresses`: :bro:type:`function` Split email addresses from MIME headers.
========================================================== ===========================================================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Functions
#########
.. bro:id:: extract_email_addrs_set

   :Type: :bro:type:`function` (str: :bro:type:`string`) : :bro:type:`set` [:bro:type:`string`]

   Extract mail addresses out of address specifications conforming to RFC5322.
   

   :str: A string potentially containing email addresses.
   

   :returns: A set of extracted email addresses.  An empty set is returned 
            if no email addresses are discovered.

.. bro:id:: extract_email_addrs_vec

   :Type: :bro:type:`function` (str: :bro:type:`string`) : :bro:type:`string_vec`

   Extract mail addresses out of address specifications conforming to RFC5322.
   

   :str: A string potentially containing email addresses.
   

   :returns: A vector of extracted email addresses.  An empty vector is returned
            if no email addresses are discovered.

.. bro:id:: extract_first_email_addr

   :Type: :bro:type:`function` (str: :bro:type:`string`) : :bro:type:`string`

   Extract the first email address from a string.
   

   :str: A string potentially containing email addresses.
   

   :returns: An email address or empty string if none found.

.. bro:id:: split_mime_email_addresses

   :Type: :bro:type:`function` (line: :bro:type:`string`) : :bro:type:`set` [:bro:type:`string`]

   Split email addresses from MIME headers.  The email addresses will
   include the display name and email address as it was given by the mail
   mail client.  Note that this currently does not account for MIME group
   addresses and won't handle them correctly.  The group name will show up
   as part of an email address.
   

   :str: The argument from a MIME header.
   

   :returns: A set of addresses or empty string if none found.


