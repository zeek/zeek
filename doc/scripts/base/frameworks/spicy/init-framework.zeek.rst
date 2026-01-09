:tocdepth: 3

base/frameworks/spicy/init-framework.zeek
=========================================
.. zeek:namespace:: Spicy


:Namespace: Spicy

Summary
~~~~~~~
Functions
#########
================================================================== =======================================================================
:zeek:id:`Spicy::disable_file_analyzer`: :zeek:type:`function`     Disable a specific Spicy file analyzer if not already inactive.
:zeek:id:`Spicy::disable_protocol_analyzer`: :zeek:type:`function` Disable a specific Spicy protocol analyzer if not already inactive.
:zeek:id:`Spicy::enable_file_analyzer`: :zeek:type:`function`      Enable a specific Spicy file analyzer if not already active.
:zeek:id:`Spicy::enable_protocol_analyzer`: :zeek:type:`function`  Enable a specific Spicy protocol analyzer if not already active.
:zeek:id:`Spicy::resource_usage`: :zeek:type:`function`            Returns current resource usage as reported by the Spicy runtime system.
================================================================== =======================================================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Functions
#########
.. zeek:id:: Spicy::disable_file_analyzer
   :source-code: base/frameworks/spicy/init-framework.zeek 77 80

   :Type: :zeek:type:`function` (tag: :zeek:type:`Files::Tag`) : :zeek:type:`bool`

   Disable a specific Spicy file analyzer if not already inactive. If
   this analyzer replaces an standard analyzer, that one will automatically
   be re-enabled.


   :param tag: analyzer to toggle


   :returns: true if the operation succeeded

.. zeek:id:: Spicy::disable_protocol_analyzer
   :source-code: base/frameworks/spicy/init-framework.zeek 67 70

   :Type: :zeek:type:`function` (tag: :zeek:type:`Analyzer::Tag`) : :zeek:type:`bool`

   Disable a specific Spicy protocol analyzer if not already inactive. If
   this analyzer replaces an standard analyzer, that one will automatically
   be re-enabled.


   :param tag: analyzer to toggle


   :returns: true if the operation succeeded

.. zeek:id:: Spicy::enable_file_analyzer
   :source-code: base/frameworks/spicy/init-framework.zeek 72 75

   :Type: :zeek:type:`function` (tag: :zeek:type:`Files::Tag`) : :zeek:type:`bool`

   Enable a specific Spicy file analyzer if not already active. If this
   analyzer replaces an standard analyzer, that one will automatically be
   disabled.


   :param tag: analyzer to toggle


   :returns: true if the operation succeeded

.. zeek:id:: Spicy::enable_protocol_analyzer
   :source-code: base/frameworks/spicy/init-framework.zeek 62 65

   :Type: :zeek:type:`function` (tag: :zeek:type:`Analyzer::Tag`) : :zeek:type:`bool`

   Enable a specific Spicy protocol analyzer if not already active. If this
   analyzer replaces an standard analyzer, that one will automatically be
   disabled.


   :param tag: analyzer to toggle


   :returns: true if the operation succeeded

.. zeek:id:: Spicy::resource_usage
   :source-code: base/frameworks/spicy/init-framework.zeek 82 85

   :Type: :zeek:type:`function` () : :zeek:type:`Spicy::ResourceUsage`

   Returns current resource usage as reported by the Spicy runtime system.


