
.. _notice-framework:

================
Notice Framework
================

One of the easiest ways to customize Zeek is writing a local notice policy.
Zeek can detect a large number of potentially interesting situations, and the
notice policy hook identifies which of them the user wants to be acted upon in
some manner. In particular, the notice policy can specify actions to be taken,
such as sending an email or compiling regular alarm emails. This page gives an
introduction into writing such a notice policy.

Overview
========

Let’s start with a little bit of background on Zeek’s philosophy on reporting
things. Zeek ships with a large number of policy scripts which perform a wide
variety of analyses. Most of these scripts monitor for activity which might be
of interest for the user. However, none of these scripts determines the
importance of what it finds itself. Instead, the scripts only flag situations
as *potentially* interesting, leaving it to the local configuration to define
which of them are in fact actionable. This decoupling of detection and
reporting allows Zeek to address the different needs that different sites have.
Definitions of what constitutes an attack or even a compromise differ quite a
bit between environments, and activity deemed malicious at one site might be
fully acceptable at another.

Whenever one of Zeek’s analysis scripts sees something potentially interesting
it flags the situation by calling the :zeek:see:`NOTICE` function and giving it
a single :zeek:see:`Notice::Info` record. A Notice has a
:zeek:see:`Notice::Type`, which reflects the kind of activity that has been
seen, and it is usually also augmented with further context about the
situation.

More information about raising notices can be found in the :ref:`Raising
Notices <raising-notices>` section.

Once a notice is raised, it can have any number of actions applied to it by
writing :zeek:see:`Notice::policy` hooks which are described in the
:ref:`Notice Policy <notice-policy>` section below. Such actions can for
example send email to configured address(es), or simply ignore the
notice. Currently, the following actions are defined:

.. list-table::
  :header-rows: 1

  * - Action
    - Description

  * - :zeek:see:`Notice::ACTION_LOG`
    - Write the notice to the :zeek:see:`Notice::LOG` logging stream.

  * - :zeek:see:`Notice::ACTION_ALARM`
    - Log into the :zeek:see:`Notice::ALARM_LOG` stream which will rotate
      hourly and email the contents to the email address or addresses in the
      :zeek:field:`Notice::Info$email_dest` field of that notice's :zeek:see:`Notice::Info` record.

  * - :zeek:see:`Notice::ACTION_EMAIL`
    - Send the notice in an email to the email address or addresses in the
      :zeek:field:`Notice::Info$email_dest` field of that notice's :zeek:see:`Notice::Info` record.

  * - :zeek:see:`Notice::ACTION_PAGE`
    - Send an email to the email address or addresses in the
      :zeek:field:`Notice::Info$email_dest` field of that notice's :zeek:see:`Notice::Info` record.

How these notice actions are applied to notices is discussed in the
:ref:`Notice Policy <notice-policy>` and :ref:`Notice Policy Shortcuts
<notice-policy-shortcuts>` sections.

Processing Notices
==================

.. _notice-policy:

Notice Policy
-------------

The hook :zeek:see:`Notice::policy` provides the mechanism for applying actions
and generally modifying the notice before it’s sent onward to the action
plugins.  Hooks can be thought of as multi-bodied functions and using them
looks very similar to handling events. The difference is that they don’t go
through the event queue like events. Users can alter notice processing by
directly modifying fields in the :zeek:see:`Notice::Info` record given as the
argument to the hook.

Here’s a simple example which tells Zeek to send an email for all notices of
type :zeek:see:`SSH::Password_Guessing` if the guesser attempted to log in to
the server at ``192.168.56.103``:

.. code-block:: zeek
  :caption: notice_ssh_guesser.zeek

  @load protocols/ssh/detect-bruteforcing

  redef SSH::password_guesses_limit=10;

  hook Notice::policy(n: Notice::Info)
      {
      if ( n$note == SSH::Password_Guessing && /192\.168\.56\.103/ in n$sub )
          {
          add n$actions[Notice::ACTION_EMAIL];
          n$email_dest = "ssh_alerts@example.net";
          }
      }

.. code-block:: console

  $ zeek -C -r ssh/sshguess.pcap notice_ssh_guesser.zeek
  $ cat notice.log

::

  #separator \x09
  #set_separator    ,
  #empty_field      (empty)
  #unset_field      -
  #path     notice
  #open     2018-12-13-22-56-35
  #fields   ts      uid     id.orig_h       id.orig_p       id.resp_h       id.resp_p       fuid    file_mime_type  file_desc       proto   note    msg     sub     src     dst     p       n       peer_descr      actions email-dest   suppress_for    dropped remote_location.country_code    remote_location.region  remote_location.city    remote_location.latitude        remote_location.longitude
  #types    time    string  addr    port    addr    port    string  string  string  enum    enum    string  string  addr    addr    port    count   string  set[enum]       set[string]   interval        bool    string  string  string  double  double
  1427726759.303199 -       -       -       -       -       -       -       -       -       SSH::Password_Guessing  192.168.56.1 appears to be guessing SSH passwords (seen in 10 connections).     Sampled servers:  192.168.56.103, 192.168.56.103, 192.168.56.103, 192.168.56.103, 192.168.56.103        192.168.56.1    -       -       -       -       Notice::ACTION_EMAIL,Notice::ACTION_LOG  ssh_alerts@example.net    3600.000000     F       -       -       -       -       -
  #close    2018-12-13-22-56-35

.. note::

  Keep in mind that the semantics of the :zeek:see:`SSH::Password_Guessing`
  notice are such that it is only raised when Zeek heuristically detects a
  failed login.

Hooks can also have priorities applied to order their execution like events
with a default priority of 0. Greater values are executed first. Setting a hook
body to run before default hook bodies might look like this:

.. code-block:: zeek

  hook Notice::policy(n: Notice::Info) &priority=5
      {
      # Insert your code here.
      }

Hooks can also abort later hook bodies with the :zeek:see:`break` keyword. This
is primarily useful if one wants to completely preempt processing by lower
priority :zeek:see:`Notice::policy` hooks.

.. _notice-policy-shortcuts:

Notice Policy Shortcuts
-----------------------

Although the notice framework provides a great deal of flexibility and
configurability there are many times that the full expressiveness isn’t needed
and actually becomes a hindrance to achieving results. The framework provides a
default :zeek:see:`Notice::policy` hook body as a way of giving users the
shortcuts to easily apply many common actions to notices.

These are implemented as sets and tables indexed with a
:zeek:see:`Notice::Type` enum value. The following table shows and describes
all of the variables available for shortcut configuration of the notice
framework.

.. list-table::
  :header-rows: 1

  * - Variable name
    - Description

  * - :zeek:see:`Notice::ignored_types`
    - Adding a :zeek:see:`Notice::Type` to this set results in the notice being
      ignored. It won’t have any other action applied to it, not even
      :zeek:see:`Notice::ACTION_LOG`.

  * - :zeek:see:`Notice::emailed_types`
    - Adding a :zeek:see:`Notice::Type` to this set results in
      :zeek:see:`Notice::ACTION_EMAIL` being applied to the notices of that
      type.

  * - :zeek:see:`Notice::alarmed_types`
    - Adding a :zeek:see:`Notice::Type` to this set results in
      :zeek:see:`Notice::ACTION_ALARM` being applied to the notices of that
      type.

  * - :zeek:see:`Notice::not_suppressed_types`
    - Adding a :zeek:see:`Notice::Type` to this set results in that notice no
      longer undergoing the normal notice suppression that would take place. Be
      careful when using this in production it could result in a dramatic
      increase in the number of notices being processed.

  * - :zeek:see:`Notice::type_suppression_intervals`
    - This is a table indexed on :zeek:see:`Notice::Type` and yielding an
      interval. It can be used as an easy way to extend the default suppression
      interval for an entire :zeek:see:`Notice::Type` without having to create
      a whole :zeek:see:`Notice::policy` entry and setting the
      ``$suppress_for`` field.

.. _raising-notices:

Raising Notices
===============

A script should raise a notice for any occurrence that a user may want to be
notified about or take action on. For example, whenever the base SSH analysis
script sees enough failed logins to a given host, it raises a notice of the
type :zeek:see:`SSH::Password_Guessing`. The code in the base SSH analysis
script which raises the notice looks like this:

.. code-block:: zeek

  NOTICE([$note=Password_Guessing,
          $msg=fmt("%s appears to be guessing SSH passwords (seen in %d connections).", key$host, r$num),
          $src=key$host,
          $identifier=cat(key$host)]);

:zeek:see:`NOTICE` is a normal function in the global namespace which wraps a
function within the Notice namespace. It takes a single argument of the
:zeek:see:`Notice::Info` record type. The most common fields used when raising
notices are described in the following table:

.. list-table::
  :header-rows: 1

  * - Field name
    - Description

  * - :zeek:field:`note`
    - This field is required and is an enum value which represents the notice
      type.

  * - :zeek:field:`msg`
    - This is a human readable message which is meant to provide more
      information about this particular instance of the notice type.

  * - :zeek:field:`sub`
    - This is a sub-message meant for human readability but will frequently
      also be used to contain data meant to be matched with the
      :zeek:see:`Notice::policy`.

  * - :zeek:field:`conn`
    - If a connection record is available when the notice is being raised and
      the notice represents some attribute of the connection, then the
      connection record can be given here. Other fields such as :zeek:field:`id` and :zeek:field:`src`
      will automatically be populated from this value.

  * - :zeek:field:`id`
    - If a :zeek:see:`conn_id` record is available when the notice is being
      raised and the notice represents some attribute of the connection, then
      the connection can be given here. Other fields such as :zeek:field:`src` will
      automatically be populated from this value.

  * - :zeek:field:`src`
    - If the notice represents an attribute of a single host then it’s possible
      that only this field should be filled out to represent the host that is
      being “noticed”.

  * - :zeek:field:`n`
    - This normally represents a number if the notice has to do with some
      number. It’s most frequently used for numeric tests in the
      :zeek:see:`Notice::policy` for making policy decisions.

  * - :zeek:field:`identifier`
    - This represents a unique identifier for this notice. This field is
      described in more detail in the :ref:`Automated Suppression
      <automated-notice-suppression>` section.

  * - :zeek:field:`suppress_for`
    - This field can be set if there is a natural suppression interval for the
      notice that may be different than the default value. The value set to
      this field can also be modified by a user’s :zeek:see:`Notice::policy` so
      the value is not set permanently and unchangeably.

When writing Zeek scripts that raise notices, some thought should be given to
what the notice represents and what data should be provided to give a consumer
of the notice the best information about the notice. If the notice is
representative of many connections and is an attribute of a host (e.g., a
scanning host) it probably makes most sense to fill out the :zeek:field:`src` field and
not give a connection or :zeek:see:`conn_id`. If a notice is representative of
a connection attribute (e.g. an apparent SSH login) then it makes sense to fill
out either :zeek:field:`Notice::Info$conn` or :zeek:field:`Notice::Info$id`
based on the data that is available when the notice is raised.

Using care when inserting data into a notice will make later analysis easier
when only the data to fully represent the occurrence that raised the notice is
available. If complete connection information is included when an SSL server
certificate is expiring, for example, the logs will be very confusing because
the connection that the certificate was detected on is a side topic to the fact
that an expired certificate was detected. It’s possible in many cases that two
or more separate notices may need to be generated. As an example, one could be
for the detection of the expired SSL certificate and another could be for if
the client decided to go ahead with the connection neglecting the expired
certificate.

.. _automated-notice-suppression:

Automated Suppression
=====================

The notice framework supports suppression for notices if the author of the
script that is generating the notice has indicated to the notice framework how
to identify notices that are intrinsically the same. Identification of these
“intrinsically duplicate” notices is implemented with an optional field in
:zeek:see:`Notice::Info` records named :zeek:field:`Notice::Info$identifier`
which is a simple string. If the :zeek:field:`Notice::Info$identifier` and
:zeek:field:`Notice::Info$note` fields are the same for two notices, the notice
framework actually considers them to be the same thing and
can use that information to suppress duplicates for a configurable period of
time.

.. note::

   If the :zeek:field:`identifier` is left out of a notice, no notice suppression takes
   place due to the framework’s inability to identify duplicates. This could be
   completely legitimate usage if no notices could ever be considered to be
   duplicates.

The :zeek:field:`Notice::Info$identifier` field typically comprises several pieces of data related to
the notice that when combined represent a unique instance of that notice. Here
is an example of the script
:doc:`/scripts/policy/protocols/ssl/validate-certs.zeek` raising a notice for
session negotiations where the certificate or certificate chain did not
validate successfully against the available certificate authority certificates.

.. code-block:: zeek

  NOTICE([$note=SSL::Invalid_Server_Cert,
          $msg=fmt("SSL certificate validation failed with (%s)", c$ssl$validation_status),
          $sub=c$ssl$subject,
          $conn=c,
          $identifier=cat(c$id$resp_h,c$id$resp_p,c$ssl$validation_status,c$ssl$cert_hash)]);

In the above example you can see that the :zeek:field:`identifier` field contains a
string that is built from the responder IP address and port, the validation
status message, and the MD5 sum of the server certificate. Those fields in
particular are chosen because different SSL certificates could be seen on any
port of a host, certificates could fail validation for different reasons, and
multiple server certificates could be used on that combination of IP address
and port with the server_name SSL extension (explaining the addition of the MD5
sum of the certificate). The result is that if a certificate fails validation
and all four pieces of data match (IP address, port, validation status, and
certificate hash) that particular notice won’t be raised again for the default
suppression period.

Setting the :zeek:field:`Notice::Info$identifier` field is left to those raising notices because it’s
assumed that the script author who is raising the notice understands the full
problem set and edge cases of the notice which may not be readily apparent to
users. If users don’t want the suppression to take place or simply want a
different interval, they can set a notice’s suppression interval to ``0secs``
or delete the value from the :zeek:field:`identifier` field in a
:zeek:see:`Notice::policy` hook.

Extending Notice Framework
==========================

There are a couple of mechanisms for extending the notice framework and adding
new capabilities.

Configuring Notice Emails
-------------------------

If :zeek:see:`Notice::mail_dest` is set, notices with an associated
e-mail action will be sent to that address. For additional
customization, users can use the :zeek:see:`Notice::policy` hook to
modify the :zeek:field:`Notice::Info$email_dest` field. The following example would result in three
separate e-mails:

.. code-block:: zeek

  hook Notice::policy(n: Notice::Info)
    {
    n$email_dest = set(
        "snow.white@example.net",
        "doc@example.net",
        "happy@example.net,sleepy@example.net,bashful@example.net"
    );
    }

You can also use :zeek:see:`Notice::policy` hooks to add extra information to
emails. The :zeek:see:`Notice::Info` record contains a vector of strings named
:zeek:field:`Notice::Info$email_body_sections` which Zeek will include verbatim when sending email.
An example of including some information from an HTTP request is included below.

.. code-block:: zeek

  hook Notice::policy(n: Notice::Info)
    {
    if ( n?$conn && n$conn?$http && n$conn$http?$host )
      n$email_body_sections[|n$email_body_sections|] = fmt("HTTP host header: %s", n$conn$http$host);
    }

Cluster Considerations
======================

When running Zeek in a cluster, most of the information above stays the same.
Notices are generated, the :zeek:see:`Notice::policy` hook is evaluated, and
any actions are run on the node which generated the notice (most often a worker
node). Of note to users/developers of Zeek is that any files or access needed
to run the notice actions must be available to the respective node(s).

The role of the manager is to receive and distribute notice suppression
information, so that duplicate notices do not get generated. Bear in mind that
some amount of latency is intrinsic in this synchronization, so it’s
possible that rapidly-generating notices will be duplicates. In this case, any
actions will also execute multiple times, once by each notice-generating
node.

The Weird Log
=============

A wide range of “weird” activity detected by Zeek can trigger corresponding
events that inform the script layer of this activity. These events exist at
various granularities, including :zeek:see:`conn_weird`,
:zeek:see:`flow_weird`, :zeek:see:`net_weird`, :zeek:see:`file_weird`, and
others. Built atop the notice framework, the :doc:`Weird
</scripts/base/frameworks/notice/weird.zeek>` module implements event handlers
that funnel the various “weirds” into the usual notice framework handlers. To
get an idea of the available weird-types, take a look at the
:zeek:see:`Weird::actions` table, which defines default actions for the various
types of activity. Weirds generally do not indicate security-relevant activity
— they’re just, well, weird things that you generally wouldn’t expect to
happen, such as odd TCP state machine violations, unexpected HTTP header
constellations, or DNS message properties that fall outside of the relevant RFC
specifications. That is, don’t consider them actionable detections in an IDS
sense, though they might well provide meaningful additional clues for a
security incident.

The notice type for weirds is :zeek:see:`Weird::Activity`. You have a wide range of actions at
your disposal for how to handle weirds: you can ignore them, log them, or have
them trigger notice, all at various reduction/filtering granularities (see the
:zeek:see:`Weird::Action` enum values for details). For dynamic filtering, the
:zeek:see:`Weird::ignore_hosts` and :zeek:see:`Weird::weird_ignore` sets allow
exclusion of activity from reporting.

The framework provides a few additional tuning knobs. See
:doc:`/scripts/base/frameworks/notice/weird.zeek` for details.
