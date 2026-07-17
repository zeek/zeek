:tocdepth: 3

base/bif/supervisor.bif.zeek
============================
.. zeek:namespace:: GLOBAL
.. zeek:namespace:: Supervisor

The BIFs that define the Zeek supervisor control interface.

:Namespaces: GLOBAL, Supervisor

Summary
~~~~~~~
Functions
#########
============================================================= =
:zeek:id:`Supervisor::__create`: :zeek:type:`function`
:zeek:id:`Supervisor::__destroy`: :zeek:type:`function`
:zeek:id:`Supervisor::__is_supervised`: :zeek:type:`function`
:zeek:id:`Supervisor::__is_supervisor`: :zeek:type:`function`
:zeek:id:`Supervisor::__node`: :zeek:type:`function`
:zeek:id:`Supervisor::__restart`: :zeek:type:`function`
:zeek:id:`Supervisor::__status`: :zeek:type:`function`
:zeek:id:`Supervisor::__stem_pid`: :zeek:type:`function`
============================================================= =


Detailed Interface
~~~~~~~~~~~~~~~~~~
Functions
#########
.. zeek:id:: Supervisor::__create
   :source-code: base/bif/supervisor.bif.zeek 29 29

   :Type: :zeek:type:`function` (node: :zeek:type:`Supervisor::NodeConfig`) : :zeek:type:`string`


.. zeek:id:: Supervisor::__destroy
   :source-code: base/bif/supervisor.bif.zeek 32 32

   :Type: :zeek:type:`function` (node: :zeek:type:`string`) : :zeek:type:`bool`


.. zeek:id:: Supervisor::__is_supervised
   :source-code: base/bif/supervisor.bif.zeek 38 38

   :Type: :zeek:type:`function` () : :zeek:type:`bool`


.. zeek:id:: Supervisor::__is_supervisor
   :source-code: base/bif/supervisor.bif.zeek 44 44

   :Type: :zeek:type:`function` () : :zeek:type:`bool`


.. zeek:id:: Supervisor::__node
   :source-code: base/bif/supervisor.bif.zeek 41 41

   :Type: :zeek:type:`function` () : :zeek:type:`Supervisor::NodeConfig`


.. zeek:id:: Supervisor::__restart
   :source-code: base/bif/supervisor.bif.zeek 35 35

   :Type: :zeek:type:`function` (node: :zeek:type:`string`) : :zeek:type:`bool`


.. zeek:id:: Supervisor::__status
   :source-code: base/bif/supervisor.bif.zeek 26 26

   :Type: :zeek:type:`function` (node: :zeek:type:`string`) : :zeek:type:`Supervisor::Status`


.. zeek:id:: Supervisor::__stem_pid
   :source-code: base/bif/supervisor.bif.zeek 47 47

   :Type: :zeek:type:`function` () : :zeek:type:`int`



