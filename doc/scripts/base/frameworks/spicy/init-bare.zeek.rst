:tocdepth: 3

base/frameworks/spicy/init-bare.zeek
====================================
.. zeek:namespace:: Spicy


:Namespace: Spicy

Summary
~~~~~~~
Redefinable Options
###################
============================================================================ ===============================================================
:zeek:id:`Spicy::abort_on_exceptions`: :zeek:type:`bool` :zeek:attr:`&redef` abort() instead of throwing HILTI exceptions.
:zeek:id:`Spicy::enable_print`: :zeek:type:`bool` :zeek:attr:`&redef`        Show output of Spicy print statements.
:zeek:id:`Spicy::enable_profiling`: :zeek:type:`bool` :zeek:attr:`&redef`    
:zeek:id:`Spicy::max_file_depth`: :zeek:type:`count` :zeek:attr:`&redef`     Maximum depth of recursive file analysis (Spicy analyzers only)
:zeek:id:`Spicy::show_backtraces`: :zeek:type:`bool` :zeek:attr:`&redef`     Include backtraces when reporting unhandled exceptions.
============================================================================ ===============================================================

Constants
#########
============================================== ===========================================
:zeek:id:`Spicy::available`: :zeek:type:`bool` Constant for testing if Spicy is available.
============================================== ===========================================

Types
#####
====================================================== ==========================================
:zeek:type:`Spicy::ResourceUsage`: :zeek:type:`record` Result type for `Spicy::resource_usage()`.
====================================================== ==========================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Redefinable Options
###################
.. zeek:id:: Spicy::abort_on_exceptions
   :source-code: base/frameworks/spicy/init-bare.zeek 16 16

   :Type: :zeek:type:`bool`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``F``

   abort() instead of throwing HILTI exceptions.

.. zeek:id:: Spicy::enable_print
   :source-code: base/frameworks/spicy/init-bare.zeek 10 10

   :Type: :zeek:type:`bool`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``F``

   Show output of Spicy print statements.

.. zeek:id:: Spicy::enable_profiling
   :source-code: base/frameworks/spicy/init-bare.zeek 13 13

   :Type: :zeek:type:`bool`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``F``


.. zeek:id:: Spicy::max_file_depth
   :source-code: base/frameworks/spicy/init-bare.zeek 22 22

   :Type: :zeek:type:`count`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``5``

   Maximum depth of recursive file analysis (Spicy analyzers only)

.. zeek:id:: Spicy::show_backtraces
   :source-code: base/frameworks/spicy/init-bare.zeek 19 19

   :Type: :zeek:type:`bool`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``F``

   Include backtraces when reporting unhandled exceptions.

Constants
#########
.. zeek:id:: Spicy::available
   :source-code: base/frameworks/spicy/init-bare.zeek 7 7

   :Type: :zeek:type:`bool`
   :Default: ``T``

   Constant for testing if Spicy is available.

Types
#####
.. zeek:type:: Spicy::ResourceUsage
   :source-code: base/frameworks/spicy/init-bare.zeek 28 36

   :Type: :zeek:type:`record`

      user_time: :zeek:type:`interval`
         user CPU time of the Zeek process

      system_time: :zeek:type:`interval`
         system CPU time of the Zeek process

      memory_heap: :zeek:type:`count`
         memory allocated on the heap by the Zeek process

      num_fibers: :zeek:type:`count`
         number of fibers currently in use

      max_fibers: :zeek:type:`count`
         maximum number of fibers ever in use

      max_fiber_stack_size: :zeek:type:`count`
         maximum fiber stack size ever in use

      cached_fibers: :zeek:type:`count`
         number of fibers currently cached

   Result type for `Spicy::resource_usage()`. The values reflect resource
   usage as reported by the Spicy runtime system.


