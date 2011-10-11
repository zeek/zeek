

Telling Bro What's Important
============================

.. class:: opening

    One of the easiest ways to customize Bro is writing a local
    *notice policy*. Bro can detect a large number of potentially
    interesting situations, and the notice policy tells which of them
    the user wants to be escalated into *alarms*. The notice policy
    can also specify further actions to be taken, such as sending an
    email. This pages gives an introduction into writing such a notice
    policy.

.. contents::

Overview
--------

Let us start with a little bit of background on Bro's philosophy on
reporting things. Bro ships with a large number of policy scripts
which perform a wide variety of analyses. Most of these scripts
monitor for activity which might be of interest for the administrator.
However, none of these scripts determines the importance of what it
finds itself. Instead, the scripts only flag situations as
*potentially* interesting, leaving it to the local configuration to
define which of them are in fact alarm-worthy. This decoupling of
detection and reporting allows Bro to address the different needs that
sites have: definitions of what constitutes an attack differ quite a
bit between environments, and activity deemed malicious at one place
might be fully acceptable at another.

Whenever one of Bro's analysis scripts sees something potentially
interesting, it flags the situation by raising a *Notice*. A Notice
has a *type*, which reflects the kind of activity that has been seen,
and it is usually also augmented with fruther *context* about the
situation. For example, whenever the HTTP analyzer sees a suspicious
URL being requested (such as ``/etc/passwd``), it raises a Notice of
the type HTTP_SensitiveURI and augments it with the requested URL
itself as well as the involved hosts.

In terms of script code, "raising a Notice" is just a call to a
predefined function called NOTICE . For example, to raise an
HTTP_SensitiveURI such a call could look like this:


.. code:: bro

    NOTICE([$note=HTTP_SensitiveURI, $conn=connection, $URL=url, ...])

If one wants to know which types of Notices a Bro script can raise,
one can just grep the script for calls to the NOTICE function.

Once raised, all Notices are processed centrally. By default, all
Notices *are* in fact automatically turned into alarms and will
therefore show up in ``alarm.log``. The local site policy can however
change this default behavior, as we describe in the following.

In general, each raised Notice gets mapped to one out of a set of
predefined *actions*. Such an action can, e.g., be to send a mail to
the administrator or to simply ignore the Notice. Currently, the
following actions are defined:

.. list-table::
    :widths: 20 80
    :header-rows: 1

    * - Action
      - Description

    * - ``NOTICE_IGNORE``
      - Ignore Notice completely.
        
    * - ``NOTICE_FILE``
      - File Notice only to ``notice.log``; do not write an entry into
        ``alarm.log``.

    * - ``NOTICE_ALARM_ALWAYS``
      - Report in ``alarm.log``.

    * - ``NOTICE_EMAIL``
      - Send out a mail and report in ``alarm.log``

    * - ``NOTICE_PAGE``
      - Page security officer and report in ``alarm.log``.

    * - ``NOTICE_DROP``
      - Block connectivity for offending IP and report in ``alarm.log``.
        
``NOTICE_ALARM_ALWAYS`` reflects the default behavior if no other
action is defined for a Notice. All notice actions except
``NOTICE_IGNORE`` also log to ``notice.log`` .

We can define which action is taken for a Notice in two ways. The
first is to generally assign an action to all instances of a
particular Notice type; the second provides the flexibility to filter
individual Notice instances independent of their type. We discuss both
in turn.

Notice Action Filters
---------------------

To generally apply the same action to all instances of a specific
type, we assign a *notice action filter* to the type. In the most
simple case, such a filter does directly correspond to the intended
action, per the following table:

.. list-table::
    :widths: 20 20
    :header-rows: 1

    * - Filter Name
      - Action

    * - ``ignore_notice``
      - ``NOTICE_IGNORE``

    * - ``file_notice``
      - ``NOTICE_FILE``

    * - ``send_email_notice``
      - ``NOTICE_EMAIL``

    * - ``send_page_notice``
      - ``NOTICE_PAGE``

    * - ``drop_source``
      - ``NOTICE_DROP``


(As ``NOTICE_ALARM_ALWAYS`` is the default action, there is no
corresponding filter).

We map a Notice type to such a filter by adding an entry to Bro's
predefined ``notice_action_filters`` table. For example, to just file
all sensitive URIs into ``notice.log`` rather than turning them into
alarms, we define:

.. code:: bro

    @load notice-action-filters
        
    redef notice_action_filters += {
            [HTTP_SensitiveURI] = file_notice
            };


Notice action filters are more powerful than just directly defining an
action. Each filter is in fact a script function which gets the Notice
instance as a parameter and returns the action Bro should take. In
general, these functions can implement arbitrary schemes to settle on
an action, which is why they are called "filters". In addition to the
filters mentioned above (which just return the corresponding action
without further ado), Bro's default script
``notice-action-filters.bro`` also defines the following ones (and
more):

.. list-table::
    :widths: 20 80
    :header-rows: 1

    * - Filter
      - Description

    * - ``tally_notice_type``
      - Count how often each Notice type occurred. The totals are
        reported when Bro terminates as new Notices of the type
        ``NoticeTally``. The original Notices are just filed into
        ``notice.log``.

    * - ``tally_notice_type_and_ignore``
      - Similar to ``tally_notice_type`` but discards original
        Notices.

    * - ``file_if_remote``
      - Do not alarm if Notice was triggered by a remote address.
        
    * - ``notice_alarm_per_orig``
      - Alarm only the first time we see the Notice type for each
        source address.

    * - ``notice_alarm_per_orig_tally``
      - Count Notice types per source address. Totals are reported, by
        default, every 5 hours as new ``NoticeTally`` Notices. The
        original Notices are just filed into ``notice.log``.

Notice Policy
-------------

The predefined set ``notice_policy`` provides the second way to define
an action to be taken for a Notice. While ``notice_action_filters``
maps all instances of a particular Notice type to the same filter,
``notice_policy`` works on individual Notice instances. Each entry of
``notice_policy`` defines (1) a condition to be matched against all
raised Notices, and (2) an action to be taken if the condition matches.

Here's a simple example which tells Bro to ignore all Notices of type
``HTTP_SensitiveURI`` if the requested URL indicates that an image was
requested (simplified example taken from
``policy/notice-policy.bro``):

.. code:: bro

    redef notice_policy += {
      [$pred(n: notice_info) = {
         return n$note == HTTP::HTTP_SensitiveURI &&
               n$URL == /.*\.(gif|jpg|png)/; 
         },
       $result = NOTICE_IGNORE]
      };


While the syntax might look a bit convoluted at first, it provides a
lot of flexibility by leveraging Bro's match-statement. ``$pred``
defines the entry's condition in the form of a predicate written as a
Bro function. The function gets passed the raised Notice and it
returns a boolean indicating whether the entry applies. If the
predicate evaluates to true, Bro takes the action specified by
``$result``. (If ``$result`` is omitted, the default action for a
matching entry is ``NOTICE_FILE``).

The ``notice_policy`` set can hold an arbitrary number of such
entries. For each Notice, Bro evaluates the predicates of all of them.
If multiple predicates evaluate to true, it is undefined which of the
matching results is taken. One can however associate a *priority* with
an entry by adding a field ``$priority=<int>`` to its definition; see
``policy/notice-policy.bro`` for examples. In the case of multiple
matches with different priorities, Bro picks the one with the highest.
If ``$priority`` is omitted, as it is in the example above, the
default priority is 1.

