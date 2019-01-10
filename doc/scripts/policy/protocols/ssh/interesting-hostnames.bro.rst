:tocdepth: 3

policy/protocols/ssh/interesting-hostnames.bro
==============================================
.. bro:namespace:: SSH

This script will generate a notice if an apparent SSH login originates 
or heads to a host with a reverse hostname that looks suspicious.  By 
default, the regular expression to match "interesting" hostnames includes 
names that are typically used for infrastructure hosts like nameservers, 
mail servers, web servers and ftp servers.

:Namespace: SSH
:Imports: :doc:`base/frameworks/notice </scripts/base/frameworks/notice/index>`

Summary
~~~~~~~
Runtime Options
###############
============================================================================ ===============================================================
:bro:id:`SSH::interesting_hostnames`: :bro:type:`pattern` :bro:attr:`&redef` Strange/bad host names to see successful SSH logins from or to.
============================================================================ ===============================================================

Redefinitions
#############
========================================== =
:bro:type:`Notice::Type`: :bro:type:`enum` 
========================================== =


Detailed Interface
~~~~~~~~~~~~~~~~~~
Runtime Options
###############
.. bro:id:: SSH::interesting_hostnames

   :Type: :bro:type:`pattern`
   :Attributes: :bro:attr:`&redef`
   :Default:

   ::

      /^?((^?((^?((^?((^?((^?((^?(^d?ns[0-9]*\.)$?)|(^?(^smtp[0-9]*\.)$?))$?)|(^?(^mail[0-9]*\.)$?))$?)|(^?(^pop[0-9]*\.)$?))$?)|(^?(^imap[0-9]*\.)$?))$?)|(^?(^www[0-9]*\.)$?))$?)|(^?(^ftp[0-9]*\.)$?))$?/

   Strange/bad host names to see successful SSH logins from or to.


