
Notice Framework
================

.. class:: opening

    One of the easiest ways to customize Bro is writing a local notice
    policy. Bro can detect a large number of potentially interesting
    situations, and the notice policy tells which of them the user wants to be
    acted upon in some manner. In particular, the notice policy can specify
    actions to be taken, such as sending an email or compiling regular
    alarm emails. This page gives an introduction into writing such a notice
    policy.

.. contents::

Overview
--------

Let us start with a little bit of background on Bro's philosophy on reporting
things. Bro ships with a large number of policy scripts which perform a wide
variety of analyses. Most of these scripts monitor for activity which might be
of interest for the user. However, none of these scripts determines the
importance of what it finds itself. Instead, the scripts only flags situations
as *potentially* interesting, leaving it to the local configuration to define
which of them are in fact actionable. This decoupling of detection and
reporting allows Bro to address the different needs that sites have:
definitions of what constitutes an attack differ quite a bit between
environments, and activity deemed malicious at one site might be fully
acceptable at another.

Whenever one of Bro's analysis scripts sees something potentially interesting
it flags the situation by calling the :bro:id:`NOTICE` function and giving it
a single :bro:type:`Notice::Info` record. A Notice has a
:bro:enum:`Notice::Type`, which reflects the kind of activity that has been
seen, and it is usually also augmented with further context about the
situation. For example, whenever the base SSH analysis scripts sees an SSH
session where it is heuristically guessed to be a successful login, it raises
a Notice of the type SSH::Login. The code in the base SSH analysis script
looks like this:

.. code:: bro

    NOTICE([$note=SSH::Login, 
            $msg="Heuristically detected successful SSH login.",
            $conn=c]);

Once a notice is raised, it can have any number of actions attached to it by
the :bro:id:`Notice::policy` which is described in the `Notice Policy`_
section below. Such actions can be to send a mail to the configured
address(es) or to simply ignore the notice. Currently, the following actions
are defined:

.. list-table::
    :widths: 20 80
    :header-rows: 1

    * - Action
      - Description

    * - :bro:enum:`Notice::ACTION_LOG`
      - Write the notice to the :bro:enum:`Notice::LOG` logging stream.

    * - :bro:enum:`Notice::ACTION_ALARM`
      - Log into the :bro:enum:`Notice::ALARM_LOG` stream which will rotate
        hourly and email the contents to the email address or addresses
        defined in the :bro:id:`Notice::mail_dest` variable.

    * - :bro:enum:`Notice::ACTION_EMAIL`
      - Send the notice in an email to the email address or addresses given in
        the :bro:id:`Notice::mail_dest` variable.

    * - :bro:enum:`Notice::ACTION_PAGE`
      - Send an email to the email address or addresses given in the
        :bro:id:`Notice::mail_page_dest` variable.

    * - :bro:enum:`Notice::ACTION_NO_SUPPRESS`
      - This action will disable the built in notice suppression for the
        notice. Keep in mind that this action will need to be attached to
        every notice that shouldn't be suppressed including each of the future
        notices that would have normally been suppressed.

How these notice actions are applied to notices is discussed in the 
`Notice Policy`_ and `Notice Policy Shortcuts`_ sections.

Notice Policy
-------------

The predefined set :bro:id:`Notice::policy` provides the mechanism for
applying actions and other behavior modifications to notices. Each entry of
:bro:id:`Notice::policy` defines a combination of several things, a condition
to be matched against all raised notices, an action to be taken if the
condition matches, and/or a interval to suppress that distinct notice with the
``$suppress_for`` field. The notice policy is defined by adding any number of
:bro:type:`Notice::Info` records to the :bro:id:`Notice::policy` set.

Here's a simple example which tells Bro to send an email for all Notices of
type :bro:enum:`SSH::Login` if the server is 10.0.0.1:

.. note::

    Keep in mind that the semantics of the :bro:enum:`SSH::Login` notice are
    such that it is only raised when Bro heuristically detects a successful
    login. No apparently failed logins will raise this notice.

.. code:: bro

    redef Notice::policy += {
      [$pred(n: Notice::Info) = {
         return n$note == SSH::Login && n$id$resp_h == 10.0.0.1;
       },
       $action = Notice::ACTION_EMAIL]
      };

While the syntax might look a bit convoluted at first, it provides a lot of
flexibility due to having access to Bro's full programming language. ``$pred``
defines the entry's condition in the form of a predicate written as a Bro
function. The function is passed the :bro:type:`Notice::Info` record and it
returns a boolean indicating whether the entry applies. If the predicate
evaluates to true (``T``), Bro applies any values found in both the
``$action`` and ``$suppress_for`` fields. The lack of a predicate in a
:bro:type:`Notice::PolicyItem` is implicitly true since an implicit false
(``F``) value would never be used.

The :bro:id:`Notice::policy` set can hold an arbitrary number of such entries.
Bro evaluates the predicates of each entry in the order defined by the
``$priority`` field. If multiple predicates evaluate to true, it is undefined
which of the matching results is taken. One can however associate a *priority*
with an entry by adding a field ``$priority=<int>`` to its definition; see
``policy/notice-policy.bro`` for examples. In the case of multiple matches
with different priorities, Bro picks the one with the highest. If
``$priority`` is omitted, as it is in the example above, the default priority
is 1.

.. code:: bro

    redef Notice::policy += {
      [$pred(n: Notice::Info) = {
         return n$note == SSH::Login && n$id$resp_h == 10.0.0.1;
       },
       $action = Notice::ACTION_EMAIL,
       $priority=5]
      };


Notice Policy Shortcuts
-----------------------

Although the notice framework provides a great deal of flexibility and
configurability there are many times that the full expressiveness isn't needed
and actually becomes a hindrance to achieving results. The framework provides
a default :bro:id:`Notice::policy` suite as a way of giving users the
shortcuts to easily apply many common actions to notices.

These are implemented as sets and tables indexed with a
:bro:enum:`Notice::Type` enum value. The following table shows and describes
all of the variables available for shortcut configuration of the notice
framework.

.. list-table::
    :widths: 32 40
    :header-rows: 1

    * - Variable name
      - Description

    * - :bro:id:`Notice::ignored_types`
      - Adding a :bro:enum:`Notice::Type` to this set results in the notice
        being ignored. It won't have any other action applied to it, not even
        :bro:enum:`Notice::ACTION_LOG`.

    * - :bro:id:`Notice::emailed_types`
      - Adding a :bro:enum:`Notice::Type` to this set results in
        :bro:enum:`Notice::ACTION_EMAIL` being applied to the notices of that
        type.

    * - :bro:id:`Notice::alarmed_types`
      - Adding a :bro:enum:`Notice::Type` to this set results in
        :bro:enum:`Notice::ACTION_ALARM` being applied to the notices of that
        type.

    * - :bro:id:`Notice::not_suppressed_types`
      - Adding a :bro:enum:`Notice::Type` to this set results in that notice
        no longer undergoing the normal notice suppression that would take
        place. Be careful when using this in production it could result in a
        dramatic increase in the number of notices being processed.


Automated Deduplication
-----------------------

Extending Notice Actions
------------------------

Extending Emails
----------------

Cluster Considerations
----------------------