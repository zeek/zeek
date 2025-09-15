:tocdepth: 3

policy/frameworks/management/supervisor/config.zeek
===================================================
.. zeek:namespace:: Management::Supervisor

Configuration settings for the Management framework's supervisor extension.

:Namespace: Management::Supervisor

Summary
~~~~~~~
Redefinable Options
###################
=========================================================================================== =================================================================
:zeek:id:`Management::Supervisor::output_max_lines`: :zeek:type:`count` :zeek:attr:`&redef` The maximum number of stdout/stderr output lines to convey in
                                                                                            :zeek:see:`Management::Supervisor::API::notify_node_exit` events.
:zeek:id:`Management::Supervisor::print_stderr`: :zeek:type:`bool` :zeek:attr:`&redef`      Whether to print the stderr sent up to the Supervisor by created
                                                                                            nodes to the terminal.
:zeek:id:`Management::Supervisor::print_stdout`: :zeek:type:`bool` :zeek:attr:`&redef`      Whether to print the stdout sent up to the Supervisor by created
                                                                                            nodes to the terminal.
:zeek:id:`Management::Supervisor::topic_prefix`: :zeek:type:`string` :zeek:attr:`&redef`    The Broker topic for Management framework communication with the
                                                                                            Supervisor.
=========================================================================================== =================================================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Redefinable Options
###################
.. zeek:id:: Management::Supervisor::output_max_lines
   :source-code: policy/frameworks/management/supervisor/config.zeek 24 24

   :Type: :zeek:type:`count`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``100``

   The maximum number of stdout/stderr output lines to convey in
   :zeek:see:`Management::Supervisor::API::notify_node_exit` events.

.. zeek:id:: Management::Supervisor::print_stderr
   :source-code: policy/frameworks/management/supervisor/config.zeek 20 20

   :Type: :zeek:type:`bool`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``F``

   Whether to print the stderr sent up to the Supervisor by created
   nodes to the terminal. By default, this is disabled since this output
   already ends up in a node-specific stderr file, per
   :zeek:see:`Management::Node::stderr_file`.

.. zeek:id:: Management::Supervisor::print_stdout
   :source-code: policy/frameworks/management/supervisor/config.zeek 14 14

   :Type: :zeek:type:`bool`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``F``

   Whether to print the stdout sent up to the Supervisor by created
   nodes to the terminal. By default, this is disabled since this output
   already ends up in a node-specific stdout file, per
   :zeek:see:`Management::Node::stdout_file`.

.. zeek:id:: Management::Supervisor::topic_prefix
   :source-code: policy/frameworks/management/supervisor/config.zeek 8 8

   :Type: :zeek:type:`string`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``"zeek/management/supervisor"``

   The Broker topic for Management framework communication with the
   Supervisor. The agent subscribes to this.


