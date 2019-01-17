:tocdepth: 3

policy/protocols/http/software.bro
==================================
.. bro:namespace:: HTTP

Software identification and extraction for HTTP traffic.

:Namespace: HTTP
:Imports: :doc:`base/frameworks/software </scripts/base/frameworks/software/index>`

Summary
~~~~~~~
Runtime Options
###############
=========================================================================== ===============================================================
:bro:id:`HTTP::ignored_user_agents`: :bro:type:`pattern` :bro:attr:`&redef` The pattern of HTTP User-Agents which you would like to ignore.
=========================================================================== ===============================================================

Redefinitions
#############
============================================ =
:bro:type:`Software::Type`: :bro:type:`enum` 
============================================ =


Detailed Interface
~~~~~~~~~~~~~~~~~~
Runtime Options
###############
.. bro:id:: HTTP::ignored_user_agents

   :Type: :bro:type:`pattern`
   :Attributes: :bro:attr:`&redef`
   :Default:

   ::

      /^?(NO_DEFAULT)$?/

   The pattern of HTTP User-Agents which you would like to ignore.


