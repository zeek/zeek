:tocdepth: 3

base/bif/file_analysis.bif.zeek
===============================
.. bro:namespace:: Files
.. bro:namespace:: GLOBAL

Internal functions and types used by the file analysis framework.

:Namespaces: Files, GLOBAL

Summary
~~~~~~~
Functions
#########
============================================================== ===================================================================
:bro:id:`Files::__add_analyzer`: :bro:type:`function`          :bro:see:`Files::add_analyzer`.
:bro:id:`Files::__analyzer_name`: :bro:type:`function`         :bro:see:`Files::analyzer_name`.
:bro:id:`Files::__disable_reassembly`: :bro:type:`function`    :bro:see:`Files::disable_reassembly`.
:bro:id:`Files::__enable_reassembly`: :bro:type:`function`     :bro:see:`Files::enable_reassembly`.
:bro:id:`Files::__file_exists`: :bro:type:`function`           :bro:see:`Files::file_exists`.
:bro:id:`Files::__lookup_file`: :bro:type:`function`           :bro:see:`Files::lookup_file`.
:bro:id:`Files::__remove_analyzer`: :bro:type:`function`       :bro:see:`Files::remove_analyzer`.
:bro:id:`Files::__set_reassembly_buffer`: :bro:type:`function` :bro:see:`Files::set_reassembly_buffer_size`.
:bro:id:`Files::__set_timeout_interval`: :bro:type:`function`  :bro:see:`Files::set_timeout_interval`.
:bro:id:`Files::__stop`: :bro:type:`function`                  :bro:see:`Files::stop`.
:bro:id:`set_file_handle`: :bro:type:`function`                For use within a :bro:see:`get_file_handle` handler to set a unique
                                                               identifier to associate with the current input to the file analysis
                                                               framework.
============================================================== ===================================================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Functions
#########
.. bro:id:: Files::__add_analyzer

   :Type: :bro:type:`function` (file_id: :bro:type:`string`, tag: :bro:type:`Files::Tag`, args: :bro:type:`any`) : :bro:type:`bool`

   :bro:see:`Files::add_analyzer`.

.. bro:id:: Files::__analyzer_name

   :Type: :bro:type:`function` (tag: :bro:type:`Files::Tag`) : :bro:type:`string`

   :bro:see:`Files::analyzer_name`.

.. bro:id:: Files::__disable_reassembly

   :Type: :bro:type:`function` (file_id: :bro:type:`string`) : :bro:type:`bool`

   :bro:see:`Files::disable_reassembly`.

.. bro:id:: Files::__enable_reassembly

   :Type: :bro:type:`function` (file_id: :bro:type:`string`) : :bro:type:`bool`

   :bro:see:`Files::enable_reassembly`.

.. bro:id:: Files::__file_exists

   :Type: :bro:type:`function` (fuid: :bro:type:`string`) : :bro:type:`bool`

   :bro:see:`Files::file_exists`.

.. bro:id:: Files::__lookup_file

   :Type: :bro:type:`function` (fuid: :bro:type:`string`) : :bro:type:`fa_file`

   :bro:see:`Files::lookup_file`.

.. bro:id:: Files::__remove_analyzer

   :Type: :bro:type:`function` (file_id: :bro:type:`string`, tag: :bro:type:`Files::Tag`, args: :bro:type:`any`) : :bro:type:`bool`

   :bro:see:`Files::remove_analyzer`.

.. bro:id:: Files::__set_reassembly_buffer

   :Type: :bro:type:`function` (file_id: :bro:type:`string`, max: :bro:type:`count`) : :bro:type:`bool`

   :bro:see:`Files::set_reassembly_buffer_size`.

.. bro:id:: Files::__set_timeout_interval

   :Type: :bro:type:`function` (file_id: :bro:type:`string`, t: :bro:type:`interval`) : :bro:type:`bool`

   :bro:see:`Files::set_timeout_interval`.

.. bro:id:: Files::__stop

   :Type: :bro:type:`function` (file_id: :bro:type:`string`) : :bro:type:`bool`

   :bro:see:`Files::stop`.

.. bro:id:: set_file_handle

   :Type: :bro:type:`function` (handle: :bro:type:`string`) : :bro:type:`any`

   For use within a :bro:see:`get_file_handle` handler to set a unique
   identifier to associate with the current input to the file analysis
   framework.  Using an empty string for the handle signifies that the
   input will be ignored/discarded.
   

   :handle: A string that uniquely identifies a file.
   
   .. bro:see:: get_file_handle


