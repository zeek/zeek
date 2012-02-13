
Notice Framework
================

.. rst-class:: opening

    One of the easiest ways to customize Bro is writing a local notice
    policy. Bro can detect a large number of potentially interesting
    situations, and the notice policy tells which of them the user wants to be
    acted upon in some manner. In particular, the notice policy can specify
    actions to be taken, such as sending an email or compiling regular
    alarm emails.  This page gives an introduction into writing such a notice
    policy.

.. contents::

Overview
--------

Let's start with a little bit of background on Bro's philosophy on reporting
things. Bro ships with a large number of policy scripts which perform a wide
variety of analyses. Most of these scripts monitor for activity which might be
of interest for the user. However, none of these scripts determines the
importance of what it finds itself. Instead, the scripts only flag situations
as *potentially* interesting, leaving it to the local configuration to define
which of them are in fact actionable. This decoupling of detection and
reporting allows Bro to address the different needs that sites have:
definitions of what constitutes an attack or even a compromise differ quite a
bit between environments, and activity deemed malicious at one site might be
fully acceptable at another.

Whenever one of Bro's analysis scripts sees something potentially
interesting it flags the situation by calling the :bro:see:`NOTICE`
function and giving it a single :bro:see:`Notice::Info` record. A Notice
has a :bro:see:`Notice::Type`, which reflects the kind of activity that
has been seen, and it is usually also augmented with further context
about the situation.

More information about raising notices can be found in the `Raising Notices`_
section.

Once a notice is raised, it can have any number of actions applied to it by
the :bro:see:`Notice::policy` set which is described in the `Notice Policy`_
section below. Such actions can be to send a mail to the configured
address(es) or to simply ignore the notice. Currently, the following actions
are defined:

.. list-table::
    :widths: 20 80
    :header-rows: 1

    * - Action
      - Description

    * - Notice::ACTION_LOG
      - Write the notice to the :bro:see:`Notice::LOG` logging stream.

    * - Notice::ACTION_ALARM
      - Log into the :bro:see:`Notice::ALARM_LOG` stream which will rotate
        hourly and email the contents to the email address or addresses
        defined in the :bro:see:`Notice::mail_dest` variable.

    * - Notice::ACTION_EMAIL
      - Send the notice in an email to the email address or addresses given in
        the :bro:see:`Notice::mail_dest` variable.

    * - Notice::ACTION_PAGE
      - Send an email to the email address or addresses given in the
        :bro:see:`Notice::mail_page_dest` variable.

    * - Notice::ACTION_NO_SUPPRESS
      - This action will disable the built in notice suppression for the
        notice. Keep in mind that this action will need to be applied to
        every notice that shouldn't be suppressed including each of the future
        notices that would have normally been suppressed.

How these notice actions are applied to notices is discussed in the 
`Notice Policy`_ and `Notice Policy Shortcuts`_ sections.

Processing Notices
------------------

Notice Policy
*************

The predefined set :bro:see:`Notice::policy` provides the mechanism for
applying actions and other behavior modifications to notices. Each entry
of :bro:see:`Notice::policy` is a record of the type
:bro:see:`Notice::PolicyItem` which defines a condition to be matched
against all raised notices and one or more of a variety of behavior
modifiers. The notice policy is defined by adding any number of
:bro:see:`Notice::PolicyItem` records to the :bro:see:`Notice::policy`
set.

Here's a simple example which tells Bro to send an email for all notices of
type :bro:see:`SSH::Login` if the server is 10.0.0.1:

.. code:: bro

    redef Notice::policy += {
      [$pred(n: Notice::Info) = {
         return n$note == SSH::Login && n$id$resp_h == 10.0.0.1;
       },
       $action = Notice::ACTION_EMAIL]
      };

.. note::

    Keep in mind that the semantics of the SSH::Login notice are
    such that it is only raised when Bro heuristically detects a successful
    login. No apparently failed logins will raise this notice.

While the syntax might look a bit convoluted at first, it provides a lot of
flexibility due to having access to Bro's full programming language.

Predicate Field
^^^^^^^^^^^^^^^

The :bro:see:`Notice::PolicyItem` record type has a field name ``$pred``
which defines the entry's condition in the form of a predicate written
as a Bro function. The function is passed the notice as a
:bro:see:`Notice::Info` record and it returns a boolean value indicating
if the entry is applicable to that particular notice.

.. note::

    The lack of a predicate in a ``Notice::PolicyItem`` is implicitly true
    (``T``) since an implicit false (``F``) value would never be used.

Bro evaluates the predicates of each entry in the order defined by the
``$priority`` field in :bro:see:`Notice::PolicyItem` records. The valid
values are 0-10 with 10 being earliest evaluated. If ``$priority`` is
omitted, the default priority is 5.

Behavior Modification Fields
^^^^^^^^^^^^^^^^^^^^^^^^^^^^

There are a set of fields in the :bro:see:`Notice::PolicyItem` record type that
indicate ways that either the notice or notice processing should be modified
if the predicate field (``$pred``) evaluated to true (``T``). Those fields are
explained in more detail in the following table.

.. list-table::
    :widths: 20 30 20
    :header-rows: 1

    * - Field
      - Description
      - Example

    * - ``$action=<Notice::Action>``
      - Each :bro:see:`Notice::PolicyItem` can have a single action
        applied to the notice with this field.
      - ``$action = Notice::ACTION_EMAIL``

    * - ``$suppress_for=<interval>`` 
      - This field makes it possible for a user to modify the behavior of the
        notice framework's automated suppression of intrinsically similar
        notices. More information about the notice framework's automated
        suppression can be found in the `Automated Suppression`_ section of
        this document.
      - ``$suppress_for = 10mins``

    * - ``$halt=<bool>``
      - This field can be used for modification of the notice policy
        evaluation. To stop processing of notice policy items before
        evaluating all of them, set this field to ``T`` and make the ``$pred``
        field return ``T``. :bro:see:`Notice::PolicyItem` records defined at
        a higher priority as defined by the ``$priority`` field will still be
        evaluated but those at a lower priority won't.
      - ``$halt = T``



.. code:: bro

    redef Notice::policy += {
      [$pred(n: Notice::Info) = {
         return n$note == SSH::Login && n$id$resp_h == 10.0.0.1;
       },
       $action = Notice::ACTION_EMAIL,
       $priority=5]
      };


Notice Policy Shortcuts
***********************

Although the notice framework provides a great deal of flexibility and
configurability there are many times that the full expressiveness isn't needed
and actually becomes a hindrance to achieving results. The framework provides
a default :bro:see:`Notice::policy` suite as a way of giving users the
shortcuts to easily apply many common actions to notices.

These are implemented as sets and tables indexed with a
:bro:see:`Notice::Type` enum value. The following table shows and describes
all of the variables available for shortcut configuration of the notice
framework.

.. list-table::
    :widths: 32 40
    :header-rows: 1

    * - Variable name
      - Description

    * - :bro:see:`Notice::ignored_types`
      - Adding a :bro:see:`Notice::Type` to this set results in the notice
        being ignored. It won't have any other action applied to it, not even
        :bro:see:`Notice::ACTION_LOG`.

    * - :bro:see:`Notice::emailed_types`
      - Adding a :bro:see:`Notice::Type` to this set results in
        :bro:see:`Notice::ACTION_EMAIL` being applied to the notices of
        that type.

    * - :bro:see:`Notice::alarmed_types`
      - Adding a :bro:see:`Notice::Type` to this set results in
        :bro:see:`Notice::ACTION_ALARM` being applied to the notices of
        that type.

    * - :bro:see:`Notice::not_suppressed_types`
      - Adding a :bro:see:`Notice::Type` to this set results in that notice
        no longer undergoing the normal notice suppression that would
        take place. Be careful when using this in production it could
        result in a dramatic increase in the number of notices being
        processed.

    * - :bro:see:`Notice::type_suppression_intervals`
      - This is a table indexed on :bro:see:`Notice::Type` and yielding an
        interval.  It can be used as an easy way to extend the default
        suppression interval for an entire :bro:see:`Notice::Type`
        without having to create a whole :bro:see:`Notice::policy` entry
        and setting the ``$suppress_for`` field.

Raising Notices
---------------

A script should raise a notice for any occurrence that a user may want
to be notified about or take action on. For example, whenever the base
SSH analysis scripts sees an SSH session where it is heuristically
guessed to be a successful login, it raises a Notice of the type
:bro:see:`SSH::Login`. The code in the base SSH analysis script looks
like this:

.. code:: bro

    NOTICE([$note=SSH::Login, 
            $msg="Heuristically detected successful SSH login.",
            $conn=c]);

:bro:see:`NOTICE` is a normal function in the global namespace which
wraps a function within the ``Notice`` namespace. It takes a single
argument of the :bro:see:`Notice::Info` record type. The most common
fields used when raising notices are described in the following table:

.. list-table::
    :widths: 32 40
    :header-rows: 1

    * - Field name
      - Description

    * - ``$note``
      - This field is required and is an enum value which represents the
        notice type.  

    * - ``$msg``
      - This is a human readable message which is meant to provide more
        information about this particular instance of the notice type.

    * - ``$sub``
      - This is a sub-message meant for human readability but will
        frequently also be used to contain data meant to be matched with the
        ``Notice::policy``.

    * - ``$conn``
      - If a connection record is available when the notice is being raised
        and the notice represents some attribute of the connection, then the
        connection record can be given here. Other fields such as ``$id`` and
        ``$src`` will automatically be populated from this value.

    * - ``$id``
      - If a conn_id record is available when the notice is being raised and
        the notice represents some attribute of the connection, then the
        connection can be given here. Other fields such as ``$src`` will
        automatically be populated from this value.

    * - ``$src``
      - If the notice represents an attribute of a single host then it's
        possible that only this field should be filled out to represent the
        host that is being "noticed".

    * - ``$n``
      - This normally represents a number if the notice has to do with some
        number. It's most frequently used for numeric tests in the
        ``Notice::policy`` for making policy decisions.

    * - ``$identifier``
      - This represents a unique identifier for this notice. This field is
        described in more detail in the `Automated Suppression`_ section.

    * - ``$suppress_for``
      - This field can be set if there is a natural suppression interval for
        the notice that may be different than the default value. The
        value set to this field can also be modified by a user's
        :bro:see:`Notice::policy` so the value is not set permanently
        and unchangeably.

When writing Bro scripts which raise notices, some thought should be given to
what the notice represents and what data should be provided to give a consumer
of the notice the best information about the notice. If the notice is
representative of many connections and is an attribute of a host (e.g. a
scanning host) it probably makes most sense to fill out the ``$src`` field and
not give a connection or conn_id. If a notice is representative of a
connection attribute (e.g. an apparent SSH login) then it makes sense to fill
out either ``$conn`` or ``$id`` based on the data that is available when the
notice is raised. Using care when inserting data into a notice will make later
analysis easier when only the data to fully represent the occurrence that
raised the notice is available. If complete connection information is
available when an SSL server certificate is expiring, the logs will be very
confusing because the connection that the certificate was detected on is a
side topic to the fact that an expired certificate was detected. It's possible
in many cases that two or more separate notices may need to be generated. As
an example, one could be for the detection of the expired SSL certificate and
another could be for if the client decided to go ahead with the connection
neglecting the expired certificate.

Automated Suppression
---------------------

The notice framework supports suppression for notices if the author of the
script that is generating the notice has indicated to the notice framework how
to identify notices that are intrinsically the same. Identification of these
"intrinsically duplicate" notices is implemented with an optional field in
:bro:see:`Notice::Info` records named ``$identifier`` which is a simple string.
If the ``$identifier`` and ``$type`` fields are the same for two notices, the
notice framework actually considers them to be the same thing and can use that
information to suppress duplicates for a configurable period of time.

.. note::

    If the ``$identifier`` is left out of a notice, no notice suppression
    takes place due to the framework's inability to identify duplicates. This
    could be completely legitimate usage if no notices could ever be
    considered to be duplicates.

The ``$identifier`` field is typically comprised of several pieces of
data related to the notice that when combined represent a unique
instance of that notice. Here is an example of the script
:doc:`scripts/policy/protocols/ssl/validate-certs` raising a notice
for session negotiations where the certificate or certificate chain did
not validate successfully against the available certificate authority
certificates.

.. code:: bro

    NOTICE([$note=SSL::Invalid_Server_Cert, 
            $msg=fmt("SSL certificate validation failed with (%s)", c$ssl$validation_status),
            $sub=c$ssl$subject, 
            $conn=c,
            $identifier=cat(c$id$resp_h,c$id$resp_p,c$ssl$validation_status,c$ssl$cert_hash)]);

In the above example you can see that the ``$identifier`` field contains a
string that is built from the responder IP address and port, the validation
status message, and the MD5 sum of the server certificate. Those fields in
particular are chosen because different SSL certificates could be seen on any
port of a host, certificates could fail validation for different reasons, and
multiple server certificates could be used on that combination of IP address
and port with the ``server_name`` SSL extension (explaining the addition of
the MD5 sum of the certificate). The result is that if a certificate fails
validation and all four pieces of data match (IP address, port, validation
status, and certificate hash) that particular notice won't be raised again for
the default suppression period.

Setting the ``$identifier`` field is left to those raising notices because
it's assumed that the script author who is raising the notice understands the
full problem set and edge cases of the notice which may not be readily
apparent to users. If users don't want the suppression to take place or simply
want a different interval, they can always modify it with the
:bro:see:`Notice::policy`.


Extending Notice Framework
--------------------------

Adding Custom Notice Actions
****************************

Extending Notice Emails
***********************

Cluster Considerations
----------------------

