:tocdepth: 3

policy/protocols/http/detect-sqli.zeek
======================================
.. zeek:namespace:: HTTP

SQL injection attack detection in HTTP.

:Namespace: HTTP
:Imports: :doc:`base/frameworks/notice </scripts/base/frameworks/notice/index>`, :doc:`base/frameworks/sumstats </scripts/base/frameworks/sumstats/index>`, :doc:`base/protocols/http </scripts/base/protocols/http/index>`

Summary
~~~~~~~
Redefinable Options
###################
================================================================================== ================================================================
:zeek:id:`HTTP::collect_SQLi_samples`: :zeek:type:`count` :zeek:attr:`&redef`      Collecting samples will add extra data to notice emails
                                                                                   by collecting some sample SQL injection url paths.
:zeek:id:`HTTP::match_sql_injection_uri`: :zeek:type:`pattern` :zeek:attr:`&redef` Regular expression is used to match URI based SQL injections.
:zeek:id:`HTTP::sqli_requests_interval`: :zeek:type:`interval` :zeek:attr:`&redef` Interval at which to watch for the
                                                                                   :zeek:id:`HTTP::sqli_requests_threshold` variable to be crossed.
:zeek:id:`HTTP::sqli_requests_threshold`: :zeek:type:`double` :zeek:attr:`&redef`  Defines the threshold that determines if an SQL injection attack
                                                                                   is ongoing based on the number of requests that appear to be SQL
                                                                                   injection attacks.
================================================================================== ================================================================

Redefinitions
#############
============================================ =
:zeek:type:`HTTP::Tags`: :zeek:type:`enum`   
:zeek:type:`Notice::Type`: :zeek:type:`enum` 
============================================ =

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
.. zeek:id:: HTTP::collect_SQLi_samples

   :Type: :zeek:type:`count`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``5``

   Collecting samples will add extra data to notice emails
   by collecting some sample SQL injection url paths.  Disable
   sample collection by setting this value to 0.

.. zeek:id:: HTTP::match_sql_injection_uri

   :Type: :zeek:type:`pattern`
   :Attributes: :zeek:attr:`&redef`
   :Default:

      ::

         /^?((^?((^?((^?((^?((^?([\?&][^[:blank:]\x00-\x37\|]+?=[\-[:alnum:]%]+([[:blank:]\x00-\x37]|\/\*.*?\*\/)*['"]?([[:blank:]\x00-\x37]|\/\*.*?\*\/|\)?;)+.*?([hH][aA][vV][iI][nN][gG]|[uU][nN][iI][oO][nN]|[eE][xX][eE][cC]|[sS][eE][lL][eE][cC][tT]|[dD][eE][lL][eE][tT][eE]|[dD][rR][oO][pP]|[dD][eE][cC][lL][aA][rR][eE]|[cC][rR][eE][aA][tT][eE]|[iI][nN][sS][eE][rR][tT])([[:blank:]\x00-\x37]|\/\*.*?\*\/)+)$?)|(^?([\?&][^[:blank:]\x00-\x37\|]+?=[\-0-9%]+([[:blank:]\x00-\x37]|\/\*.*?\*\/)*['"]?([[:blank:]\x00-\x37]|\/\*.*?\*\/|\)?;)+([xX]?[oO][rR]|[nN]?[aA][nN][dD])([[:blank:]\x00-\x37]|\/\*.*?\*\/)+['"]?(([^a-zA-Z&]+)?=|[eE][xX][iI][sS][tT][sS]))$?))$?)|(^?([\?&][^[:blank:]\x00-\x37]+?=[\-0-9%]*([[:blank:]\x00-\x37]|\/\*.*?\*\/)*['"]([[:blank:]\x00-\x37]|\/\*.*?\*\/)*(-|=|\+|\|\|)([[:blank:]\x00-\x37]|\/\*.*?\*\/)*([0-9]|\(?[cC][oO][nN][vV][eE][rR][tT]|[cC][aA][sS][tT]))$?))$?)|(^?([\?&][^[:blank:]\x00-\x37\|]+?=([[:blank:]\x00-\x37]|\/\*.*?\*\/)*['"]([[:blank:]\x00-\x37]|\/\*.*?\*\/|;)*([xX]?[oO][rR]|[nN]?[aA][nN][dD]|[hH][aA][vV][iI][nN][gG]|[uU][nN][iI][oO][nN]|[eE][xX][eE][cC]|[sS][eE][lL][eE][cC][tT]|[dD][eE][lL][eE][tT][eE]|[dD][rR][oO][pP]|[dD][eE][cC][lL][aA][rR][eE]|[cC][rR][eE][aA][tT][eE]|[rR][eE][gG][eE][xX][pP]|[iI][nN][sS][eE][rR][tT])([[:blank:]\x00-\x37]|\/\*.*?\*\/|[\[(])+[a-zA-Z&]{2,})$?))$?)|(^?([\?&][^[:blank:]\x00-\x37]+?=[^\.]*?([cC][hH][aA][rR]|[aA][sS][cC][iI][iI]|[sS][uU][bB][sS][tT][rR][iI][nN][gG]|[tT][rR][uU][nN][cC][aA][tT][eE]|[vV][eE][rR][sS][iI][oO][nN]|[lL][eE][nN][gG][tT][hH])\()$?))$?)|(^?(\/\*![[:digit:]]{5}.*?\*\/)$?))$?/


   Regular expression is used to match URI based SQL injections.

.. zeek:id:: HTTP::sqli_requests_interval

   :Type: :zeek:type:`interval`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``5.0 mins``

   Interval at which to watch for the
   :zeek:id:`HTTP::sqli_requests_threshold` variable to be crossed.
   At the end of each interval the counter is reset.

.. zeek:id:: HTTP::sqli_requests_threshold

   :Type: :zeek:type:`double`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``50.0``

   Defines the threshold that determines if an SQL injection attack
   is ongoing based on the number of requests that appear to be SQL
   injection attacks.

Hooks
#####
.. zeek:id:: HTTP::sqli_policy

   :Type: :zeek:type:`hook` (c: :zeek:type:`connection`, method: :zeek:type:`string`, unescaped_URI: :zeek:type:`string`) : :zeek:type:`bool`

   A hook that can be used to prevent specific requests from being counted
   as an injection attempt.  Use a 'break' statement to exit the hook
   early and ignore the request.


