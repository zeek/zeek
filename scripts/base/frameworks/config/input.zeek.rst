:tocdepth: 3

base/frameworks/config/input.zeek
=================================
.. bro:namespace:: Config

File input for the configuration framework using the input framework.

:Namespace: Config
:Imports: :doc:`base/frameworks/cluster </scripts/base/frameworks/cluster/index>`, :doc:`base/frameworks/config/main.zeek </scripts/base/frameworks/config/main.zeek>`

Summary
~~~~~~~
Redefinable Options
###################
================================================================== ===============================================
:bro:id:`Config::config_files`: :bro:type:`set` :bro:attr:`&redef` Configuration files that will be read off disk.
================================================================== ===============================================

Functions
#########
=================================================== ===================================================================
:bro:id:`Config::read_config`: :bro:type:`function` Read specified configuration file and apply values; updates to file
                                                    are not tracked.
=================================================== ===================================================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Redefinable Options
###################
.. bro:id:: Config::config_files

   :Type: :bro:type:`set` [:bro:type:`string`]
   :Attributes: :bro:attr:`&redef`
   :Default: ``{}``

   Configuration files that will be read off disk. Files are reread
   every time they are updated so updates should be atomic with "mv"
   instead of writing the file in place.
   
   If the same configuration option is defined in several files with
   different values, behavior is unspecified.

Functions
#########
.. bro:id:: Config::read_config

   :Type: :bro:type:`function` (filename: :bro:type:`string`) : :bro:type:`void`

   Read specified configuration file and apply values; updates to file
   are not tracked.


