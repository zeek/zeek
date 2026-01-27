
======================
 Scripting Frameworks
======================

Zeek includes several software frameworks that provide commonly used
functionality to the scripting layer. Among other things, these frameworks
enhance Zeek’s ability to ingest data, structure and filter its outputs, adapt
settings at runtime, and interact with other components in your network. Most
frameworks include functionality implemented in Zeek’s core, with
corresponding data structures and APIs exposed to the script layer.

Some frameworks target relatively specific use cases, while others run in
nearly every Zeek installation. The logging framework, for example, provides
the machinery behind all of the Zeek logs covered earlier. Frameworks also
build on each other, so it’s well worth knowing their capabilities. The next
sections cover them in detail.

.. toctree::
   :maxdepth: 1

   broker
   cluster
   configuration
   file-analysis
   input
   intel
   logging
   management
   netcontrol
   notice
   packet-analysis
   signatures
   storage
   sumstats
   supervisor
   telemetry
   tls-decryption
