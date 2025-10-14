:tocdepth: 3

base/frameworks/config/input.zeek
=================================
.. zeek:namespace:: Config

File input for the configuration framework using the input framework.

:Namespace: Config
:Imports: :doc:`base/frameworks/cluster </scripts/base/frameworks/cluster/index>`, :doc:`base/frameworks/config/main.zeek </scripts/base/frameworks/config/main.zeek>`

Summary
~~~~~~~
Redefinable Options
###################
===================================================================== ===============================================
:zeek:id:`Config::config_files`: :zeek:type:`set` :zeek:attr:`&redef` Configuration files that will be read off disk.
===================================================================== ===============================================

Functions
#########
===================================================== ===================================================================
:zeek:id:`Config::read_config`: :zeek:type:`function` Read specified configuration file and apply values; updates to file
                                                      are not tracked.
===================================================== ===================================================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Redefinable Options
###################
.. zeek:id:: Config::config_files
   :source-code: base/frameworks/config/input.zeek 15 15

   :Type: :zeek:type:`set` [:zeek:type:`string`]
   :Attributes: :zeek:attr:`&redef`
   :Default: ``{}``

   Configuration files that will be read off disk. Files are reread
   every time they are updated so updates should be atomic with "mv"
   instead of writing the file in place.
   
   If the same configuration option is defined in several files with
   different values, behavior is unspecified.

Functions
#########
.. zeek:id:: Config::read_config
   :source-code: base/frameworks/config/input.zeek 61 77

   :Type: :zeek:type:`function` (filename: :zeek:type:`string`) : :zeek:type:`void`

   Read specified configuration file and apply values; updates to file
   are not tracked.


