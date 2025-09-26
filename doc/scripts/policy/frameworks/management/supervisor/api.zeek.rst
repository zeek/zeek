:tocdepth: 3

policy/frameworks/management/supervisor/api.zeek
================================================
.. zeek:namespace:: Management::Supervisor::API


:Namespace: Management::Supervisor::API
:Imports: :doc:`policy/frameworks/management/types.zeek </scripts/policy/frameworks/management/types.zeek>`

Summary
~~~~~~~
Events
######
============================================================================ =====================================================================
:zeek:id:`Management::Supervisor::API::notify_node_exit`: :zeek:type:`event` The Supervisor generates this event whenever it has received a status
                                                                             update from the stem, indicating that a node exited.
============================================================================ =====================================================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Events
######
.. zeek:id:: Management::Supervisor::API::notify_node_exit
   :source-code: policy/frameworks/management/agent/main.zeek 263 269

   :Type: :zeek:type:`event` (node: :zeek:type:`string`, outputs: :zeek:type:`Management::NodeOutputs`)

   The Supervisor generates this event whenever it has received a status
   update from the stem, indicating that a node exited.
   

   :param node: the name of a node previously created via
       :zeek:see:`Supervisor::create`.
   

   :param outputs: stdout/stderr context for the node. The contained strings
       span up to the 100 most recent lines in the corresponding
       stream. See :zeek:see:`Management::Supervisor::output_max_lines`
       to adjust the line limit.
   


