
.. _bro-ids:

=======
Bro IDS
=======

An Intrusion Detection System (IDS) allows you to detect suspicious
activities happening on your network as a result of a past or active
attack. Because of its programming capabilities, Bro can easily be
configured to behave like traditional IDSs and detect common attacks
with well known patterns, or you can create your own scripts to detect
conditions specific to your particular case.

In the following sections, we present a few examples of common uses of
Bro as an IDS.

-------------------------------------------------
Detecting an FTP Brute-force Attack and Notifying
-------------------------------------------------

For the purpose of this exercise, we define FTP brute-forcing as too many
rejected usernames and passwords occurring from a single address.  We
start by defining a threshold for the number of attempts, a monitoring
interval (in minutes), and a new notice type.

.. btest-include:: ${BRO_SRC_ROOT}/scripts/policy/protocols/ftp/detect-bruteforcing.bro
    :lines: 9-25

Using the ftp_reply event, we check for error codes from the `500
series <http://en.wikipedia.org/wiki/List_of_FTP_server_return_codes>`_
for the "USER" and "PASS" commands, representing rejected usernames or
passwords. For this, we can use the :bro:see:`FTP::parse_ftp_reply_code`
function to break down the reply code and check if the first digit is a
"5" or not. If true, we then use the :ref:`Summary Statistics Framework
<sumstats-framework>` to keep track of the number of failed attempts.

.. btest-include:: ${BRO_SRC_ROOT}/scripts/policy/protocols/ftp/detect-bruteforcing.bro
    :lines: 52-60

Next, we use the SumStats framework to raise a notice of the attack when
the number of failed attempts exceeds the specified threshold during the
measuring interval.

.. btest-include:: ${BRO_SRC_ROOT}/scripts/policy/protocols/ftp/detect-bruteforcing.bro
    :lines: 28-50

Below is the final code for our script.

.. btest-include:: ${BRO_SRC_ROOT}/scripts/policy/protocols/ftp/detect-bruteforcing.bro

.. btest:: ftp-bruteforce

    @TEST-EXEC: btest-rst-cmd bro -r ${TRACES}/ftp/bruteforce.pcap protocols/ftp/detect-bruteforcing.bro
    @TEST-EXEC: btest-rst-include notice.log

As a final note, the :doc:`detect-bruteforcing.bro
</scripts/policy/protocols/ftp/detect-bruteforcing.bro>` script above is
included with Bro out of the box.  Use this feature by loading this script
during startup.

-------------
Other Attacks
-------------

Detecting SQL Injection Attacks
-------------------------------

Checking files against known malware hashes
-------------------------------------------

Files transmitted on your network could either be completely harmless or
contain viruses and other threats. One possible action against this
threat is to compute the hashes of the files and compare them against a
list of known malware hashes. Bro simplifies this task by offering a
:doc:`detect-MHR.bro </scripts/policy/frameworks/files/detect-MHR.bro>`
script that creates and compares hashes against the `Malware Hash
Registry <https://www.team-cymru.org/Services/MHR/>`_ maintained by Team
Cymru. Use this feature by loading this script during startup.
