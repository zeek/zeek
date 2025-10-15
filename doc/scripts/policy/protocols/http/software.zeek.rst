:tocdepth: 3

policy/protocols/http/software.zeek
===================================
.. zeek:namespace:: HTTP

Software identification and extraction for HTTP traffic.

:Namespace: HTTP
:Imports: :doc:`base/frameworks/software </scripts/base/frameworks/software/index>`

Summary
~~~~~~~
Runtime Options
###############
============================================================================== ===============================================================
:zeek:id:`HTTP::ignored_user_agents`: :zeek:type:`pattern` :zeek:attr:`&redef` The pattern of HTTP User-Agents which you would like to ignore.
============================================================================== ===============================================================

Redefinitions
#############
============================================== ========================================================
:zeek:type:`Software::Type`: :zeek:type:`enum` 
                                               
                                               * :zeek:enum:`HTTP::APPSERVER`:
                                                 Identifier for app servers in the software framework.
                                               
                                               * :zeek:enum:`HTTP::BROWSER`:
                                                 Identifier for web browsers in the software framework.
                                               
                                               * :zeek:enum:`HTTP::SERVER`:
                                                 Identifier for web servers in the software framework.
============================================== ========================================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Runtime Options
###############
.. zeek:id:: HTTP::ignored_user_agents
   :source-code: policy/protocols/http/software.zeek 18 18

   :Type: :zeek:type:`pattern`
   :Attributes: :zeek:attr:`&redef`
   :Default:

      ::

         /^?(NO_DEFAULT)$?/


   The pattern of HTTP User-Agents which you would like to ignore.


