:tocdepth: 3

policy/protocols/http/detect-sql-injection.zeek
===============================================
.. zeek:namespace:: HTTP

SQL injection attack detection in HTTP.

The script annotates the notices it generates with an associated $uid
connection identifier; always provides an attacker IP address in the
$src field; and always provides a victim IP address in the $dst field.

:Namespace: HTTP
:Imports: :doc:`base/frameworks/notice </scripts/base/frameworks/notice/index>`, :doc:`base/frameworks/sumstats </scripts/base/frameworks/sumstats/index>`, :doc:`base/protocols/http </scripts/base/protocols/http/index>`

Summary
~~~~~~~
Redefinable Options
###################
================================================================================== ================================================================
:zeek:id:`HTTP::match_sql_injection_uri`: :zeek:type:`pattern` :zeek:attr:`&redef` Regular expression is used to match URI based SQL injections.
:zeek:id:`HTTP::sqli_requests_interval`: :zeek:type:`interval` :zeek:attr:`&redef` Interval at which to watch for the
                                                                                   :zeek:id:`HTTP::sqli_requests_threshold` variable to be crossed.
:zeek:id:`HTTP::sqli_requests_threshold`: :zeek:type:`double` :zeek:attr:`&redef`  Defines the threshold that determines if an SQL injection attack
                                                                                   is ongoing based on the number of requests that appear to be SQL
                                                                                   injection attacks.
================================================================================== ================================================================

Redefinitions
#############
======================================================= ==============================================================
:zeek:type:`HTTP::Tags`: :zeek:type:`enum`

                                                        * :zeek:enum:`HTTP::URI_SQLI`:
                                                          Indicator of a URI based SQL injection attack.
:zeek:type:`Notice::Type`: :zeek:type:`enum`

                                                        * :zeek:enum:`HTTP::SQL_Injection_Attacker`:
                                                          Indicates that a host performing SQL injection attacks was
                                                          detected.

                                                        * :zeek:enum:`HTTP::SQL_Injection_Victim`:
                                                          Indicates that a host was seen to have SQL injection attacks
                                                          against it.
:zeek:type:`SumStats::Observation`: :zeek:type:`record`

                                                        :New Fields: :zeek:type:`SumStats::Observation`

                                                          uid: :zeek:type:`string` :zeek:attr:`&optional`
======================================================= ==============================================================

Hooks
#####
=============================================== =======================================================================
:zeek:id:`HTTP::sqli_policy`: :zeek:type:`hook` A hook that can be used to prevent specific requests from being counted
                                                as an injection attempt.
=============================================== =======================================================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Redefinable Options
###################
.. zeek:id:: HTTP::match_sql_injection_uri
   :source-code: policy/protocols/http/detect-sql-injection.zeek 41 41

   :Type: :zeek:type:`pattern`
   :Attributes: :zeek:attr:`&redef`
   :Default:

      ::

         /^?((^?((^?((^?((^?(((?i:^?([\?&][^[:blank:]\x00-\x1f\|\+]+?=[\-[:alnum:]%]+([[:blank:]\x00-\x1f\+]|\/\*.*?\*\/)*'?([[:blank:]\x00-\x1f\+]|\/\*.*?\*\/|\)?;)+.*?(having|union|exec|select|delete|drop|declare|create|insert)([[:blank:]\x00-\x1f\+]|\/\*.*?\*\/)+)$?))|((?i:^?([\?&][^[:blank:]\x00-\x1f\|\+]+?=[\-0-9%]+([[:blank:]\x00-\x1f\+]|\/\*.*?\*\/)*'?([[:blank:]\x00-\x1f\+]|\/\*.*?\*\/|\)?;)+(x?or|n?and)([[:blank:]\x00-\x1f\+]|\/\*.*?\*\/)+'?(([^a-zA-Z&]+)?=|exists))$?)))$?)|((?i:^?([\?&][^[:blank:]\x00-\x1f\+]+?=[\-0-9%]*([[:blank:]\x00-\x1f\+]|\/\*.*?\*\/)*'([[:blank:]\x00-\x1f]|\/\*.*?\*\/)*(-|=|\+|\|\|)([[:blank:]\x00-\x1f\+]|\/\*.*?\*\/)*([0-9]|\(?convert|cast))$?)))$?)|((?i:^?([\?&][^[:blank:]\x00-\x1f\|\+]+?=([[:blank:]\x00-\x1f\+]|\/\*.*?\*\/)*'([[:blank:]\x00-\x1f\+]|\/\*.*?\*\/|;)*(x?or|n?and|having|union|exec|select|delete|drop|declare|create|regexp|insert)([[:blank:]\x00-\x1f\+]|\/\*.*?\*\/|[\[(])+[a-zA-Z&]{2,})$?)))$?)|((?i:^?([\?&][^[:blank:]\x00-\x1f\+]+?=[^\.]*?(char|ascii|substring|truncate|version|length)\()$?)))$?)|(^?(\/\*![[:digit:]]{5}.*?\*\/)$?))$?/


   Regular expression is used to match URI based SQL injections.

.. zeek:id:: HTTP::sqli_requests_interval
   :source-code: policy/protocols/http/detect-sql-injection.zeek 38 38

   :Type: :zeek:type:`interval`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``5.0 mins``

   Interval at which to watch for the
   :zeek:id:`HTTP::sqli_requests_threshold` variable to be crossed.
   At the end of each interval the counter is reset.

.. zeek:id:: HTTP::sqli_requests_threshold
   :source-code: policy/protocols/http/detect-sql-injection.zeek 33 33

   :Type: :zeek:type:`double`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``50.0``

   Defines the threshold that determines if an SQL injection attack
   is ongoing based on the number of requests that appear to be SQL
   injection attacks.

Hooks
#####
.. zeek:id:: HTTP::sqli_policy
   :source-code: policy/protocols/http/detect-sql-injection.zeek 52 52

   :Type: :zeek:type:`hook` (c: :zeek:type:`connection`, method: :zeek:type:`string`, unescaped_URI: :zeek:type:`string`) : :zeek:type:`bool`

   A hook that can be used to prevent specific requests from being counted
   as an injection attempt.  Use a 'break' statement to exit the hook
   early and ignore the request.


