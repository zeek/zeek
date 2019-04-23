:tocdepth: 3

base/bif/file_analysis.bif.zeek
===============================
.. zeek:namespace:: Files
.. zeek:namespace:: GLOBAL

Internal functions and types used by the file analysis framework.

:Namespaces: Files, GLOBAL

Summary
~~~~~~~
Functions
#########
================================================================ ====================================================================
:zeek:id:`Files::__add_analyzer`: :zeek:type:`function`          :zeek:see:`Files::add_analyzer`.
:zeek:id:`Files::__analyzer_name`: :zeek:type:`function`         :zeek:see:`Files::analyzer_name`.
:zeek:id:`Files::__disable_reassembly`: :zeek:type:`function`    :zeek:see:`Files::disable_reassembly`.
:zeek:id:`Files::__enable_reassembly`: :zeek:type:`function`     :zeek:see:`Files::enable_reassembly`.
:zeek:id:`Files::__file_exists`: :zeek:type:`function`           :zeek:see:`Files::file_exists`.
:zeek:id:`Files::__lookup_file`: :zeek:type:`function`           :zeek:see:`Files::lookup_file`.
:zeek:id:`Files::__remove_analyzer`: :zeek:type:`function`       :zeek:see:`Files::remove_analyzer`.
:zeek:id:`Files::__set_reassembly_buffer`: :zeek:type:`function` :zeek:see:`Files::set_reassembly_buffer_size`.
:zeek:id:`Files::__set_timeout_interval`: :zeek:type:`function`  :zeek:see:`Files::set_timeout_interval`.
:zeek:id:`Files::__stop`: :zeek:type:`function`                  :zeek:see:`Files::stop`.
:zeek:id:`set_file_handle`: :zeek:type:`function`                For use within a :zeek:see:`get_file_handle` handler to set a unique
                                                                 identifier to associate with the current input to the file analysis
                                                                 framework.
================================================================ ====================================================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Functions
#########
.. zeek:id:: Files::__add_analyzer

   :Type: :zeek:type:`function` (file_id: :zeek:type:`string`, tag: :zeek:type:`Files::Tag`, args: :zeek:type:`any`) : :zeek:type:`bool`

   :zeek:see:`Files::add_analyzer`.

.. zeek:id:: Files::__analyzer_name

   :Type: :zeek:type:`function` (tag: :zeek:type:`Files::Tag`) : :zeek:type:`string`

   :zeek:see:`Files::analyzer_name`.

.. zeek:id:: Files::__disable_reassembly

   :Type: :zeek:type:`function` (file_id: :zeek:type:`string`) : :zeek:type:`bool`

   :zeek:see:`Files::disable_reassembly`.

.. zeek:id:: Files::__enable_reassembly

   :Type: :zeek:type:`function` (file_id: :zeek:type:`string`) : :zeek:type:`bool`

   :zeek:see:`Files::enable_reassembly`.

.. zeek:id:: Files::__file_exists

   :Type: :zeek:type:`function` (fuid: :zeek:type:`string`) : :zeek:type:`bool`

   :zeek:see:`Files::file_exists`.

.. zeek:id:: Files::__lookup_file

   :Type: :zeek:type:`function` (fuid: :zeek:type:`string`) : :zeek:type:`fa_file`

   :zeek:see:`Files::lookup_file`.

.. zeek:id:: Files::__remove_analyzer

   :Type: :zeek:type:`function` (file_id: :zeek:type:`string`, tag: :zeek:type:`Files::Tag`, args: :zeek:type:`any`) : :zeek:type:`bool`

   :zeek:see:`Files::remove_analyzer`.

.. zeek:id:: Files::__set_reassembly_buffer

   :Type: :zeek:type:`function` (file_id: :zeek:type:`string`, max: :zeek:type:`count`) : :zeek:type:`bool`

   :zeek:see:`Files::set_reassembly_buffer_size`.

.. zeek:id:: Files::__set_timeout_interval

   :Type: :zeek:type:`function` (file_id: :zeek:type:`string`, t: :zeek:type:`interval`) : :zeek:type:`bool`

   :zeek:see:`Files::set_timeout_interval`.

.. zeek:id:: Files::__stop

   :Type: :zeek:type:`function` (file_id: :zeek:type:`string`) : :zeek:type:`bool`

   :zeek:see:`Files::stop`.

.. zeek:id:: set_file_handle

   :Type: :zeek:type:`function` (handle: :zeek:type:`string`) : :zeek:type:`any`

   For use within a :zeek:see:`get_file_handle` handler to set a unique
   identifier to associate with the current input to the file analysis
   framework.  Using an empty string for the handle signifies that the
   input will be ignored/discarded.
   

   :handle: A string that uniquely identifies a file.
   
   .. zeek:see:: get_file_handle


