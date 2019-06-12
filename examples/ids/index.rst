
.. _bro-ids:

.. _zeek-ids:

===
IDS
===

An Intrusion Detection System (IDS) allows you to detect suspicious
activities happening on your network as a result of a past or active
attack. Because of its programming capabilities, Zeek can easily be
configured to behave like traditional IDSs and detect common attacks
with well known patterns, or you can create your own scripts to detect
conditions specific to your particular case.

In the following sections, we present a few examples of common uses of
Zeek as an IDS.

-------------------------------------------------
Detecting an FTP Brute-force Attack and Notifying
-------------------------------------------------

For the purpose of this exercise, we define FTP brute-forcing as too many
rejected usernames and passwords occurring from a single address.  We
start by defining a threshold for the number of attempts, a monitoring
interval (in minutes), and a new notice type.

.. sourcecode:: zeek
   :caption: detect-bruteforcing.zeek

   module FTP;

   export {
       redef enum Notice::Type += {
           ## Indicates a host bruteforcing FTP logins by watching for too
           ## many rejected usernames or failed passwords.
           Bruteforcing
       };

       ## How many rejected usernames or passwords are required before being
       ## considered to be bruteforcing.
       const bruteforce_threshold: double = 20 &redef;

       ## The time period in which the threshold needs to be crossed before
       ## being reset.
       const bruteforce_measurement_interval = 15mins &redef;
   }

Using the ftp_reply event, we check for error codes from the `500
series <http://en.wikipedia.org/wiki/List_of_FTP_server_return_codes>`_
for the "USER" and "PASS" commands, representing rejected usernames or
passwords. For this, we can use the :zeek:see:`FTP::parse_ftp_reply_code`
function to break down the reply code and check if the first digit is a
"5" or not. If true, we then use the :ref:`Summary Statistics Framework
<sumstats-framework>` to keep track of the number of failed attempts.

.. sourcecode:: zeek
   :caption: detect-bruteforcing.zeek

   event ftp_reply(c: connection, code: count, msg: string, cont_resp: bool)
       {
       local cmd = c$ftp$cmdarg$cmd;
       if ( cmd == "USER" || cmd == "PASS" )
           {
           if ( FTP::parse_ftp_reply_code(code)$x == 5 )
               SumStats::observe("ftp.failed_auth", [$host=c$id$orig_h], [$str=cat(c$id$resp_h)]);
           }
       }

Next, we use the SumStats framework to raise a notice of the attack when
the number of failed attempts exceeds the specified threshold during the
measuring interval.

.. sourcecode:: zeek
   :caption: detect-bruteforcing.zeek

   event zeek_init()
       {
       local r1: SumStats::Reducer = [$stream="ftp.failed_auth", $apply=set(SumStats::UNIQUE), $unique_max=double_to_count(bruteforce_threshold+2)];
       SumStats::create([$name="ftp-detect-bruteforcing",
                         $epoch=bruteforce_measurement_interval,
                         $reducers=set(r1),
                         $threshold_val(key: SumStats::Key, result: SumStats::Result) =
                             {
                             return result["ftp.failed_auth"]$num+0.0;
                             },
                         $threshold=bruteforce_threshold,
                         $threshold_crossed(key: SumStats::Key, result: SumStats::Result) =
                             {
                             local r = result["ftp.failed_auth"];
                             local dur = duration_to_mins_secs(r$end-r$begin);
                             local plural = r$unique>1 ? "s" : "";
                             local message = fmt("%s had %d failed logins on %d FTP server%s in %s", key$host, r$num, r$unique, plural, dur);
                             NOTICE([$note=FTP::Bruteforcing,
                                     $src=key$host,
                                     $msg=message,
                                     $identifier=cat(key$host)]);
                             }]);
       }

Below is the final code for our script.

.. sourcecode:: zeek
   :caption: detect-bruteforcing.zeek

   ##! FTP brute-forcing detector, triggering when too many rejected usernames or
   ##! failed passwords have occurred from a single address.

   @load base/protocols/ftp
   @load base/frameworks/sumstats

   @load base/utils/time

   module FTP;

   export {
       redef enum Notice::Type += {
           ## Indicates a host bruteforcing FTP logins by watching for too
           ## many rejected usernames or failed passwords.
           Bruteforcing
       };

       ## How many rejected usernames or passwords are required before being
       ## considered to be bruteforcing.
       const bruteforce_threshold: double = 20 &redef;

       ## The time period in which the threshold needs to be crossed before
       ## being reset.
       const bruteforce_measurement_interval = 15mins &redef;
   }


   event zeek_init()
       {
       local r1: SumStats::Reducer = [$stream="ftp.failed_auth", $apply=set(SumStats::UNIQUE), $unique_max=double_to_count(bruteforce_threshold+2)];
       SumStats::create([$name="ftp-detect-bruteforcing",
                         $epoch=bruteforce_measurement_interval,
                         $reducers=set(r1),
                         $threshold_val(key: SumStats::Key, result: SumStats::Result) =
                             {
                             return result["ftp.failed_auth"]$num+0.0;
                             },
                         $threshold=bruteforce_threshold,
                         $threshold_crossed(key: SumStats::Key, result: SumStats::Result) =
                             {
                             local r = result["ftp.failed_auth"];
                             local dur = duration_to_mins_secs(r$end-r$begin);
                             local plural = r$unique>1 ? "s" : "";
                             local message = fmt("%s had %d failed logins on %d FTP server%s in %s", key$host, r$num, r$unique, plural, dur);
                             NOTICE([$note=FTP::Bruteforcing,
                                     $src=key$host,
                                     $msg=message,
                                     $identifier=cat(key$host)]);
                             }]);
       }

   event ftp_reply(c: connection, code: count, msg: string, cont_resp: bool)
       {
       local cmd = c$ftp$cmdarg$cmd;
       if ( cmd == "USER" || cmd == "PASS" )
           {
           if ( FTP::parse_ftp_reply_code(code)$x == 5 )
               SumStats::observe("ftp.failed_auth", [$host=c$id$orig_h], [$str=cat(c$id$resp_h)]);
           }
       }

.. sourcecode:: console

   $ zeek -r ftp/bruteforce.pcap protocols/ftp/detect-bruteforcing.zeek
   $ cat notice.log
   #separator \x09
   #set_separator    ,
   #empty_field      (empty)
   #unset_field      -
   #path     notice
   #open     2018-12-13-22-56-21
   #fields   ts      uid     id.orig_h       id.orig_p       id.resp_h       id.resp_p       fuid    file_mime_type  file_desc       proto   note    msg     sub     src     dst     p       n       peer_descr      actions suppress_for    dropped remote_location.country_code    remote_location.region  remote_location.city    remote_location.latitude        remote_location.longitude
   #types    time    string  addr    port    addr    port    string  string  string  enum    enum    string  string  addr    addr    port    count   string  set[enum]       interval        bool    string  string  string  double  double
   1389721084.522861 -       -       -       -       -       -       -       -       -       FTP::Bruteforcing       192.168.56.1 had 20 failed logins on 1 FTP server in 0m37s      -       192.168.56.1    -       -       -       -       Notice::ACTION_LOG      3600.000000     F       -       -       -       -       -
   #close    2018-12-13-22-56-21

As a final note, the :doc:`detect-bruteforcing.zeek
</scripts/policy/protocols/ftp/detect-bruteforcing.zeek>` script above is
included with Zeek out of the box.  Use this feature by loading this script
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
list of known malware hashes. Zeek simplifies this task by offering a
:doc:`detect-MHR.zeek </scripts/policy/frameworks/files/detect-MHR.zeek>`
script that creates and compares hashes against the `Malware Hash
Registry <https://www.team-cymru.org/Services/MHR/>`_ maintained by Team
Cymru. Use this feature by loading this script during startup.
