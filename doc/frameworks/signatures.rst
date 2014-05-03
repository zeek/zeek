
===================
Signature Framework
===================

.. rst-class:: opening

    Bro relies primarily on its extensive scripting language for 
    defining and analyzing detection policies. In addition, however,
    Bro also provides an independent *signature language* for doing
    low-level, Snort-style pattern matching. While signatures are
    *not* Bro's preferred detection tool, they sometimes come in handy
    and are closer to what many people are familiar with from using
    other NIDS. This page gives a brief overview on Bro's signatures
    and covers some of their technical subtleties.

.. contents::
    :depth: 2

Basics
======

Let's look at an example signature first:

.. code:: bro-sig

    signature my-first-sig {
        ip-proto == tcp
        dst-port == 80
        payload /.*root/
        event "Found root!"
    }
    

This signature asks Bro to match the regular expression ``.*root`` on
all TCP connections going to port 80. When the signature triggers, Bro
will raise an event :bro:id:`signature_match` of the form:

.. code:: bro

    event signature_match(state: signature_state, msg: string, data: string)
    
Here, ``state`` contains more information on the connection that
triggered the match, ``msg`` is the string specified by the
signature's event statement (``Found root!``), and data is the last
piece of payload which triggered the pattern match.

To turn such :bro:id:`signature_match` events into actual alarms, you can
load Bro's :doc:`/scripts/base/frameworks/signatures/main.bro` script.
This script contains a default event handler that raises
:bro:enum:`Signatures::Sensitive_Signature` :doc:`Notices <notice>`
(as well as others; see the beginning of the script).

As signatures are independent of Bro's policy scripts, they are put into
their own file(s). There are three ways to specify which files contain
signatures: By using the ``-s`` flag when you invoke Bro, or by
extending the Bro variable :bro:id:`signature_files` using the ``+=``
operator, or by using the ``@load-sigs`` directive inside a Bro script.
If a signature file is given without a full path, it is searched for
along the normal ``BROPATH``.  Additionally, the ``@load-sigs``
directive can be used to load signature files in a path relative to the
Bro script in which it's placed, e.g. ``@load-sigs ./mysigs.sig`` will
expect that signature file in the same directory as the Bro script. The
default extension of the file name is ``.sig``, and Bro appends that
automatically when necessary.

Signature Language for Network Traffic
======================================

Let's look at the format of a signature more closely. Each individual
signature has the format ``signature <id> { <attributes> }``. ``<id>``
is a unique label for the signature. There are two types of
attributes: *conditions* and *actions*. The conditions define when the
signature matches, while the actions declare what to do in the case of
a match. Conditions can be further divided into four types: *header*,
*content*, *dependency*, and *context*. We discuss these all in more
detail in the following.

Conditions
----------

Header Conditions
~~~~~~~~~~~~~~~~~

Header conditions limit the applicability of the signature to a subset
of traffic that contains matching packet headers.  This type of matching
is performed only for the first packet of a connection.

There are pre-defined header conditions for some of the most used
header fields. All of them generally have the format ``<keyword> <cmp>
<value-list>``, where ``<keyword>`` names the header field; ``cmp`` is
one of ``==``, ``!=``, ``<``, ``<=``, ``>``, ``>=``; and
``<value-list>`` is a list of comma-separated values to compare
against. The following keywords are defined:

``src-ip``/``dst-ip <cmp> <address-list>``
    Source and destination address, respectively. Addresses can be given
    as IPv4 or IPv6 addresses or CIDR masks.  For IPv6 addresses/masks
    the colon-hexadecimal representation of the address must be enclosed
    in square brackets (e.g. ``[fe80::1]`` or ``[fe80::0]/16``).

``src-port``/``dst-port <cmp> <int-list>``
    Source and destination port, respectively.

``ip-proto <cmp> tcp|udp|icmp|icmp6|ip|ip6``
    IPv4 header's Protocol field or the Next Header field of the final
    IPv6 header (i.e. either Next Header field in the fixed IPv6 header
    if no extension headers are present or that field from the last
    extension header in the chain).  Note that the IP-in-IP forms of
    tunneling are automatically decapsulated by default and signatures
    apply to only the inner-most packet, so specifying ``ip`` or ``ip6``
    is a no-op.

For lists of multiple values, they are sequentially compared against
the corresponding header field. If at least one of the comparisons
evaluates to true, the whole header condition matches (exception: with
``!=``, the header condition only matches if all values differ).

In addition to these pre-defined header keywords, a general header
condition can be defined either as

.. code:: bro-sig

    header <proto>[<offset>:<size>] [& <integer>] <cmp> <value-list>

This compares the value found at the given position of the packet header
with a list of values. ``offset`` defines the position of the value
within the header of the protocol defined by ``proto`` (which can be
``ip``, ``ip6``, ``tcp``, ``udp``, ``icmp`` or ``icmp6``). ``size`` is
either 1, 2, or 4 and specifies the value to have a size of this many
bytes. If the optional ``& <integer>`` is given, the packet's value is
first masked with the integer before it is compared to the value-list.
``cmp`` is one of ``==``, ``!=``, ``<``, ``<=``, ``>``, ``>=``.
``value-list`` is a list of comma-separated integers similar to those
described above.  The integers within the list may be followed by an
additional ``/ mask`` where ``mask`` is a value from 0 to 32. This
corresponds to the CIDR notation for netmasks and is translated into a
corresponding bitmask applied to the packet's value prior to the
comparison (similar to the optional ``& integer``).  IPv6 address values
are not allowed in the value-list, though you can still inspect any 1,
2, or 4 byte section of an IPv6 header using this keyword.

Putting it all together, this is an example condition that is
equivalent to ``dst-ip == 1.2.3.4/16, 5.6.7.8/24``:

.. code:: bro-sig

    header ip[16:4] == 1.2.3.4/16, 5.6.7.8/24

Note that the analogous example for IPv6 isn't currently possible since
4 bytes is the max width of a value that can be compared.

Content Conditions
~~~~~~~~~~~~~~~~~~

Content conditions are defined by regular expressions. We
differentiate two kinds of content conditions: first, the expression
may be declared with the ``payload`` statement, in which case it is
matched against the raw payload of a connection (for reassembled TCP
streams) or of each packet (for ICMP, UDP, and non-reassembled TCP).
Second, it may be prefixed with an analyzer-specific label, in which
case the expression is matched against the data as extracted by the
corresponding analyzer.

A ``payload`` condition has the form:

.. code:: bro-sig

    payload /<regular expression>/

Currently, the following analyzer-specific content conditions are
defined (note that the corresponding analyzer has to be activated by
loading its policy script):

``http-request /<regular expression>/``
    The regular expression is matched against decoded URIs of HTTP
    requests. Obsolete alias: ``http``.

``http-request-header /<regular expression>/``
    The regular expression is matched against client-side HTTP headers.

``http-request-body /<regular expression>/``
    The regular expression is matched against client-side bodys of
    HTTP requests.

``http-reply-header /<regular expression>/``
    The regular expression is matched against server-side HTTP headers.

``http-reply-body /<regular expression>/``
    The regular expression is matched against server-side bodys of
    HTTP replys.

``ftp /<regular expression>/``
    The regular expression is matched against the command line input
    of FTP sessions.

``finger /<regular expression>/``
    The regular expression is matched against finger requests.

For example, ``http-request /.*(etc/(passwd|shadow)/`` matches any URI
containing either ``etc/passwd`` or ``etc/shadow``. To filter on request
types, e.g. ``GET``, use ``payload /GET /``.

Note that HTTP pipelining (that is, multiple HTTP transactions in a
single TCP connection) has some side effects on signature matches. If
multiple conditions are specified within a single signature, this
signature matches if all conditions are met by any HTTP transaction
(not necessarily always the same!) in a pipelined connection.

Dependency Conditions
~~~~~~~~~~~~~~~~~~~~~

To define dependencies between signatures, there are two conditions:


``requires-signature [!] <id>``
    Defines the current signature to match only if the signature given
    by ``id`` matches for the same connection. Using ``!`` negates the
    condition: The current signature only matches if ``id`` does not
    match for the same connection (using this defers the match
    decision until the connection terminates).

``requires-reverse-signature [!] <id>``
    Similar to ``requires-signature``, but ``id`` has to match for the
    opposite direction of the same connection, compared to the current
    signature. This allows to model the notion of requests and
    replies.

Context Conditions
~~~~~~~~~~~~~~~~~~

Context conditions pass the match decision on to other components of
Bro. They are only evaluated if all other conditions have already
matched. The following context conditions are defined:

``eval <policy-function>``
    The given policy function is called and has to return a boolean
    confirming the match. If false is returned, no signature match is
    going to be triggered. The function has to be of type ``function
    cond(state: signature_state, data: string): bool``. Here,
    ``data`` may contain the most recent content chunk available at
    the time the signature was matched. If no such chunk is available,
    ``data`` will be the empty string. See :bro:type:`signature_state`
    for its definition.

``payload-size <cmp> <integer>``
    Compares the integer to the size of the payload of a packet. For
    reassembled TCP streams, the integer is compared to the size of
    the first in-order payload chunk. Note that the latter is not very
    well defined.

``same-ip``
    Evaluates to true if the source address of the IP packets equals
    its destination address.

``tcp-state <state-list>``
    Imposes restrictions on the current TCP state of the connection.
    ``state-list`` is a comma-separated list of the keywords
    ``established`` (the three-way handshake has already been
    performed), ``originator`` (the current data is send by the
    originator of the connection), and ``responder`` (the current data
    is send by the responder of the connection).


Actions
-------

Actions define what to do if a signature matches. Currently, there are
two actions defined:

``event <string>``
    Raises a :bro:id:`signature_match` event. The event handler has the
    following type:

    .. code:: bro

        event signature_match(state: signature_state, msg: string, data: string)

    The given string is passed in as ``msg``, and data is the current
    part of the payload that has eventually lead to the signature
    match (this may be empty for signatures without content
    conditions).

``enable <string>``
    Enables the protocol analyzer ``<string>`` for the matching
    connection (``"http"``, ``"ftp"``, etc.). This is used by Bro's
    dynamic protocol detection to activate analyzers on the fly.

Signature Language for File Content
===================================

The signature framework can also be used to identify MIME types of files
irrespective of the network protocol/connection over which the file is
transferred.  A special type of signature can be written for this
purpose and will be used automatically by the :doc:`Files Framework
<file-analysis>` or by Bro scripts that use the :bro:see:`file_magic`
built-in function.

Conditions
----------

File signatures use a single type of content condition in the form of a
regular expression:

``file-magic /<regular expression>/``

This is analogous to the ``payload`` content condition for the network
traffic signature language described above.  The difference is that
``payload`` signatures are applied to payloads of network connections,
but ``file-magic`` can be applied to any arbitrary data, it does not
have to be tied to a network protocol/connection.

Actions
-------

Upon matching a chunk of data, file signatures use the following action
to get information about that data's MIME type:

``file-mime <string> [, <integer>]``

The arguments include the MIME type string associated with the file
magic regular expression and an optional "strength" as a signed integer.
Since multiple file magic signatures may match against a given chunk of
data, the strength value may be used to help choose a "winner".  Higher
values are considered stronger.

Things to keep in mind when writing signatures
==============================================

* Each signature is reported at most once for every connection,
  further matches of the same signature are ignored.

* The content conditions perform pattern matching on elements
  extracted from an application protocol dialogue. For example, ``http
  /.*passwd/`` scans URLs requested within HTTP sessions. The thing to
  keep in mind here is that these conditions only perform any matching
  when the corresponding application analyzer is actually *active* for
  a connection. Note that by default, analyzers are not enabled if the
  corresponding Bro script has not been loaded. A good way to
  double-check whether an analyzer "sees" a connection is checking its
  log file for corresponding entries. If you cannot find the
  connection in the analyzer's log, very likely the signature engine
  has also not seen any application data.

* As the name indicates, the ``payload`` keyword matches on packet
  *payload* only. You cannot use it to match on packet headers; use
  the header conditions for that.

* For TCP connections, header conditions are only evaluated for the
  *first packet from each endpoint*. If a header condition does not
  match the initial packets, the signature will not trigger. Bro
  optimizes for the most common application here, which is header
  conditions selecting the connections to be examined more closely
  with payload statements.

* For UDP and ICMP flows, the payload matching is done on a per-packet
  basis; i.e., any content crossing packet boundaries will not be
  found. For TCP connections, the matching semantics depend on whether
  Bro is *reassembling* the connection (i.e., putting all of a
  connection's packets in sequence). By default, Bro is reassembling
  the first 1K of every TCP connection, which means that within this
  window, matches will be found without regards to packet order or
  boundaries (i.e., *stream-wise matching*).

* For performance reasons, by default Bro *stops matching* on a
  connection after seeing 1K of payload; see the section on options
  below for how to change this behaviour. The default was chosen with
  Bro's main user of signatures in mind: dynamic protocol detection
  works well even when examining just connection heads.

* Regular expressions are implicitly anchored, i.e., they work as if
  prefixed with the ``^`` operator. For reassembled TCP connections,
  they are anchored at the first byte of the payload *stream*. For all
  other connections, they are anchored at the first payload byte of
  each packet. To match at arbitrary positions, you can prefix the
  regular expression with ``.*``, as done in the examples above.

* To match on non-ASCII characters, Bro's regular expressions support
  the ``\x<hex>`` operator. CRs/LFs are not treated specially by the
  signature engine and can be matched with ``\r`` and ``\n``,
  respectively. Generally, Bro follows `flex's regular expression
  syntax
  <http://flex.sourceforge.net/manual/Patterns.html>`_.
  See the DPD signatures in ``base/frameworks/dpd/dpd.sig`` for some examples
  of fairly complex payload patterns.

* The data argument of the :bro:id:`signature_match` handler might not carry
  the full text matched by the regular expression. Bro performs the
  matching incrementally as packets come in; when the signature
  eventually fires, it can only pass on the most recent chunk of data.


Options
=======

The following options control details of Bro's matching process:

``dpd_reassemble_first_packets: bool`` (default: ``T``)
    If true, Bro reassembles the beginning of every TCP connection (of
    up to ``dpd_buffer_size`` bytes, see below), to facilitate
    reliable matching across packet boundaries. If false, only
    connections are reassembled for which an application-layer
    analyzer gets activated (e.g., by Bro's dynamic protocol
    detection).

``dpd_match_only_beginning : bool`` (default: ``T``)
    If true, Bro performs packet matching only within the initial
    payload window of ``dpd_buffer_size``. If false, it keeps matching
    on subsequent payload as well.

``dpd_buffer_size: count`` (default: ``1024``)
    Defines the buffer size for the two preceding options. In
    addition, this value determines the amount of bytes Bro buffers
    for each connection in order to activate application analyzers
    even after parts of the payload have already passed through. This
    is needed by the dynamic protocol detection capability to defer
    the decision which analyzers to use.


So, how about using Snort signatures with Bro?
==============================================

There was once a script, ``snort2bro``, that converted Snort
signatures automatically into Bro's signature syntax. However, in our
experience this didn't turn out to be a very useful thing to do
because by simply using Snort signatures, one can't benefit from the
additional capabilities that Bro provides; the approaches of the two
systems are just too different. We therefore stopped maintaining the
``snort2bro`` script, and there are now many newer Snort options which
it doesn't support. The script is now no longer part of the Bro
distribution.

