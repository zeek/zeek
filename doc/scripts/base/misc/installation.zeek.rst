:tocdepth: 3

base/misc/installation.zeek
===========================
.. zeek:namespace:: Installation

This module collects properties of the Zeek installation.

Directories are absolute and guaranteed to exist. Not all are necessarily in
operational use -- this depends on how you're running Zeek (as a standalone
process or clusterized, via zeekctl or the Management framework, etc).

For details about Zeek's version, see the :zeek:see:`Version` module.

:Namespace: Installation

Summary
~~~~~~~
Constants
#########
======================================================= ============================================
:zeek:id:`Installation::etc_dir`: :zeek:type:`string`   The installation's configuration directory.
:zeek:id:`Installation::log_dir`: :zeek:type:`string`   The installation's log directory.
:zeek:id:`Installation::root_dir`: :zeek:type:`string`  Zeek installation root directory.
:zeek:id:`Installation::spool_dir`: :zeek:type:`string` The installation's spool directory.
:zeek:id:`Installation::state_dir`: :zeek:type:`string` The installation's variable-state directory.
======================================================= ============================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Constants
#########
.. zeek:id:: Installation::etc_dir
   :source-code: base/misc/installation.zeek 15 15

   :Type: :zeek:type:`string`
   :Default: ``"/usr/local/zeek/etc"``

   The installation's configuration directory.

.. zeek:id:: Installation::log_dir
   :source-code: base/misc/installation.zeek 18 18

   :Type: :zeek:type:`string`
   :Default: ``"/usr/local/zeek/logs"``

   The installation's log directory.

.. zeek:id:: Installation::root_dir
   :source-code: base/misc/installation.zeek 12 12

   :Type: :zeek:type:`string`
   :Default: ``"/usr/local/zeek"``

   Zeek installation root directory.

.. zeek:id:: Installation::spool_dir
   :source-code: base/misc/installation.zeek 21 21

   :Type: :zeek:type:`string`
   :Default: ``"/usr/local/zeek/spool"``

   The installation's spool directory.

.. zeek:id:: Installation::state_dir
   :source-code: base/misc/installation.zeek 24 24

   :Type: :zeek:type:`string`
   :Default: ``"/usr/local/zeek/var/lib"``

   The installation's variable-state directory.


