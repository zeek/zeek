:tocdepth: 3

base/frameworks/cluster/nodes/logger.zeek
=========================================

This is the core Zeek script to support the notion of a cluster logger.

The logger is passive (other Zeek instances connect to us), and once
connected the logger receives logs from other Zeek instances.
This script will be automatically loaded if necessary based on the
type of node being started.
This is where the cluster logger sets it's specific settings for other
frameworks and in the core.


Summary
~~~~~~~
State Variables
###############
======================================================================== =============================================================================
:zeek:id:`archiver_log_metadata`: :zeek:type:`table` :zeek:attr:`&redef` Generic log metadata rendered into filename that zeek-archiver may interpret.
======================================================================== =============================================================================

Redefinitions
#############
=========================================================================================== ==========================================================================
:zeek:id:`Log::default_mail_alarms_interval`: :zeek:type:`interval` :zeek:attr:`&redef`     Alarm summary mail interval.
:zeek:id:`Log::default_rotation_interval`: :zeek:type:`interval` :zeek:attr:`&redef`        Log rotation interval.
:zeek:id:`Log::default_rotation_postprocessor_cmd`: :zeek:type:`string` :zeek:attr:`&redef` Use the cluster's archive logging script.
:zeek:id:`Log::enable_local_logging`: :zeek:type:`bool` :zeek:attr:`&redef`                 Turn on local logging.
:zeek:id:`Log::enable_remote_logging`: :zeek:type:`bool` :zeek:attr:`&redef`                Turn off remote logging since this is the logger and should only log here.
=========================================================================================== ==========================================================================

Functions
#########
=============================================================== =========================================================================
:zeek:id:`archiver_encode_log_metadata`: :zeek:type:`function`  Encode the given table as zeek-archiver understood metadata part.
:zeek:id:`archiver_rotation_format_func`: :zeek:type:`function` This function will rotate logs in a format compatible with zeek-archiver.
=============================================================== =========================================================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
State Variables
###############
.. zeek:id:: archiver_log_metadata
   :source-code: base/frameworks/cluster/nodes/logger.zeek 26 26

   :Type: :zeek:type:`table` [:zeek:type:`string`] of :zeek:type:`string`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``{}``

   Generic log metadata rendered into filename that zeek-archiver may interpret.

Functions
#########
.. zeek:id:: archiver_encode_log_metadata
   :source-code: base/frameworks/cluster/nodes/logger.zeek 39 57

   :Type: :zeek:type:`function` (tbl: :zeek:type:`table` [:zeek:type:`string`] of :zeek:type:`string`) : :zeek:type:`string`

   Encode the given table as zeek-archiver understood metadata part.

.. zeek:id:: archiver_rotation_format_func
   :source-code: base/frameworks/cluster/nodes/logger.zeek 62 73

   :Type: :zeek:type:`function` (ri: :zeek:type:`Log::RotationFmtInfo`) : :zeek:type:`Log::RotationPath`

   This function will rotate logs in a format compatible with zeek-archiver.
   If you're using the Supervisor framework, this function will be used,
   if not, you can set :zeek:see:`Log::rotation_format_func` to this function.


