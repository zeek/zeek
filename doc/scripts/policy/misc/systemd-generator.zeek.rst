:tocdepth: 3

policy/misc/systemd-generator.zeek
==================================


:Imports: :doc:`base/frameworks/cluster </scripts/base/frameworks/cluster/index>`, :doc:`base/frameworks/cluster/nodes/logger.zeek </scripts/base/frameworks/cluster/nodes/logger.zeek>`, :doc:`base/frameworks/logging </scripts/base/frameworks/logging/index>`

Summary
~~~~~~~
Redefinitions
#############
=========================================================================================== =
:zeek:id:`Log::default_rotation_dir`: :zeek:type:`string` :zeek:attr:`&redef`
:zeek:id:`Log::default_rotation_postprocessor_cmd`: :zeek:type:`string` :zeek:attr:`&redef`
:zeek:id:`Log::rotation_format_func`: :zeek:type:`function` :zeek:attr:`&redef`
:zeek:id:`LogAscii::enable_leftover_log_rotation`: :zeek:type:`bool` :zeek:attr:`&redef`
=========================================================================================== =


Detailed Interface
~~~~~~~~~~~~~~~~~~

