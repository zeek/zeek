:tocdepth: 3

policy/protocols/ssh/interesting-hostnames.zeek
===============================================
.. zeek:namespace:: SSH

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
=============================================================================== ===============================================================
:zeek:id:`SSH::interesting_hostnames`: :zeek:type:`pattern` :zeek:attr:`&redef` Strange/bad host names to see successful SSH logins from or to.
=============================================================================== ===============================================================

Redefinitions
#############
============================================ ===============================================================
:zeek:type:`Notice::Type`: :zeek:type:`enum` 
                                             
                                             * :zeek:enum:`SSH::Interesting_Hostname_Login`:
                                               Generated if a login originates or responds with a host where
                                               the reverse hostname lookup resolves to a name matched by the
                                               :zeek:id:`SSH::interesting_hostnames` regular expression.
============================================ ===============================================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Runtime Options
###############
.. zeek:id:: SSH::interesting_hostnames
   :source-code: policy/protocols/ssh/interesting-hostnames.zeek 20 20

   :Type: :zeek:type:`pattern`
   :Attributes: :zeek:attr:`&redef`
   :Default:

      ::

         /^?((^?((^?((^?((^?((^?((^?(^d?ns[0-9]*\.)$?)|(^?(^smtp[0-9]*\.)$?))$?)|(^?(^mail[0-9]*\.)$?))$?)|(^?(^pop[0-9]*\.)$?))$?)|(^?(^imap[0-9]*\.)$?))$?)|(^?(^www[0-9]*\.)$?))$?)|(^?(^ftp[0-9]*\.)$?))$?/


   Strange/bad host names to see successful SSH logins from or to.


