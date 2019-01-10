:tocdepth: 3

policy/protocols/http/detect-sqli.bro
=====================================
.. bro:namespace:: HTTP

SQL injection attack detection in HTTP.

:Namespace: HTTP
:Imports: :doc:`base/frameworks/notice </scripts/base/frameworks/notice/index>`, :doc:`base/frameworks/sumstats </scripts/base/frameworks/sumstats/index>`, :doc:`base/protocols/http </scripts/base/protocols/http/index>`

Summary
~~~~~~~
Redefinable Options
###################
=============================================================================== ================================================================
:bro:id:`HTTP::collect_SQLi_samples`: :bro:type:`count` :bro:attr:`&redef`      Collecting samples will add extra data to notice emails
                                                                                by collecting some sample SQL injection url paths.
:bro:id:`HTTP::match_sql_injection_uri`: :bro:type:`pattern` :bro:attr:`&redef` Regular expression is used to match URI based SQL injections.
:bro:id:`HTTP::sqli_requests_interval`: :bro:type:`interval` :bro:attr:`&redef` Interval at which to watch for the
                                                                                :bro:id:`HTTP::sqli_requests_threshold` variable to be crossed.
:bro:id:`HTTP::sqli_requests_threshold`: :bro:type:`double` :bro:attr:`&redef`  Defines the threshold that determines if an SQL injection attack
                                                                                is ongoing based on the number of requests that appear to be SQL
                                                                                injection attacks.
=============================================================================== ================================================================

Redefinitions
#############
========================================== =
:bro:type:`HTTP::Tags`: :bro:type:`enum`   
:bro:type:`Notice::Type`: :bro:type:`enum` 
========================================== =

Hooks
#####
============================================= =======================================================================
:bro:id:`HTTP::sqli_policy`: :bro:type:`hook` A hook that can be used to prevent specific requests from being counted
                                              as an injection attempt.
============================================= =======================================================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Redefinable Options
###################
.. bro:id:: HTTP::collect_SQLi_samples

   :Type: :bro:type:`count`
   :Attributes: :bro:attr:`&redef`
   :Default: ``5``

   Collecting samples will add extra data to notice emails
   by collecting some sample SQL injection url paths.  Disable
   sample collection by setting this value to 0.

.. bro:id:: HTTP::match_sql_injection_uri

   :Type: :bro:type:`pattern`
   :Attributes: :bro:attr:`&redef`
   :Default:

   ::

      /^?((^?((^?((^?((^?((^?([\?&][^[:blank:]\x00-\x37\|]+?=[\-[:alnum:]%]+([[:blank:]\x00-\x37]|\/\*.*?\*\/)*['"]?([[:blank:]\x00-\x37]|\/\*.*?\*\/|\)?;)+.*?([hH][aA][vV][iI][nN][gG]|[uU][nN][iI][oO][nN]|[eE][xX][eE][cC]|[sS][eE][lL][eE][cC][tT]|[dD][eE][lL][eE][tT][eE]|[dD][rR][oO][pP]|[dD][eE][cC][lL][aA][rR][eE]|[cC][rR][eE][aA][tT][eE]|[iI][nN][sS][eE][rR][tT])([[:blank:]\x00-\x37]|\/\*.*?\*\/)+)$?)|(^?([\?&][^[:blank:]\x00-\x37\|]+?=[\-0-9%]+([[:blank:]\x00-\x37]|\/\*.*?\*\/)*['"]?([[:blank:]\x00-\x37]|\/\*.*?\*\/|\)?;)+([xX]?[oO][rR]|[nN]?[aA][nN][dD])([[:blank:]\x00-\x37]|\/\*.*?\*\/)+['"]?(([^a-zA-Z&]+)?=|[eE][xX][iI][sS][tT][sS]))$?))$?)|(^?([\?&][^[:blank:]\x00-\x37]+?=[\-0-9%]*([[:blank:]\x00-\x37]|\/\*.*?\*\/)*['"]([[:blank:]\x00-\x37]|\/\*.*?\*\/)*(-|=|\+|\|\|)([[:blank:]\x00-\x37]|\/\*.*?\*\/)*([0-9]|\(?[cC][oO][nN][vV][eE][rR][tT]|[cC][aA][sS][tT]))$?))$?)|(^?([\?&][^[:blank:]\x00-\x37\|]+?=([[:blank:]\x00-\x37]|\/\*.*?\*\/)*['"]([[:blank:]\x00-\x37]|\/\*.*?\*\/|;)*([xX]?[oO][rR]|[nN]?[aA][nN][dD]|[hH][aA][vV][iI][nN][gG]|[uU][nN][iI][oO][nN]|[eE][xX][eE][cC]|[sS][eE][lL][eE][cC][tT]|[dD][eE][lL][eE][tT][eE]|[dD][rR][oO][pP]|[dD][eE][cC][lL][aA][rR][eE]|[cC][rR][eE][aA][tT][eE]|[rR][eE][gG][eE][xX][pP]|[iI][nN][sS][eE][rR][tT])([[:blank:]\x00-\x37]|\/\*.*?\*\/|[\[(])+[a-zA-Z&]{2,})$?))$?)|(^?([\?&][^[:blank:]\x00-\x37]+?=[^\.]*?([cC][hH][aA][rR]|[aA][sS][cC][iI][iI]|[sS][uU][bB][sS][tT][rR][iI][nN][gG]|[tT][rR][uU][nN][cC][aA][tT][eE]|[vV][eE][rR][sS][iI][oO][nN]|[lL][eE][nN][gG][tT][hH])\()$?))$?)|(^?(\/\*![[:digit:]]{5}.*?\*\/)$?))$?/

   Regular expression is used to match URI based SQL injections.

.. bro:id:: HTTP::sqli_requests_interval

   :Type: :bro:type:`interval`
   :Attributes: :bro:attr:`&redef`
   :Default: ``5.0 mins``

   Interval at which to watch for the
   :bro:id:`HTTP::sqli_requests_threshold` variable to be crossed.
   At the end of each interval the counter is reset.

.. bro:id:: HTTP::sqli_requests_threshold

   :Type: :bro:type:`double`
   :Attributes: :bro:attr:`&redef`
   :Default: ``50.0``

   Defines the threshold that determines if an SQL injection attack
   is ongoing based on the number of requests that appear to be SQL
   injection attacks.

Hooks
#####
.. bro:id:: HTTP::sqli_policy

   :Type: :bro:type:`hook` (c: :bro:type:`connection`, method: :bro:type:`string`, unescaped_URI: :bro:type:`string`) : :bro:type:`bool`

   A hook that can be used to prevent specific requests from being counted
   as an injection attempt.  Use a 'break' statement to exit the hook
   early and ignore the request.


