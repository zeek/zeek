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
:zeek:id:`Files::__analyzer_enabled`: :zeek:type:`function`      :zeek:see:`Files::analyzer_enabled`.
:zeek:id:`Files::__analyzer_name`: :zeek:type:`function`         :zeek:see:`Files::analyzer_name`.
:zeek:id:`Files::__disable_analyzer`: :zeek:type:`function`      :zeek:see:`Files::disable_analyzer`.
:zeek:id:`Files::__disable_reassembly`: :zeek:type:`function`    :zeek:see:`Files::disable_reassembly`.
:zeek:id:`Files::__enable_analyzer`: :zeek:type:`function`       :zeek:see:`Files::enable_analyzer`.
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
   :source-code: base/bif/file_analysis.bif.zeek 42 42

   :Type: :zeek:type:`function` (file_id: :zeek:type:`string`, tag: :zeek:type:`Files::Tag`, args: :zeek:type:`any`) : :zeek:type:`bool`

   :zeek:see:`Files::add_analyzer`.

.. zeek:id:: Files::__analyzer_enabled
   :source-code: base/bif/file_analysis.bif.zeek 38 38

   :Type: :zeek:type:`function` (tag: :zeek:type:`Files::Tag`) : :zeek:type:`bool`

   :zeek:see:`Files::analyzer_enabled`.

.. zeek:id:: Files::__analyzer_name
   :source-code: base/bif/file_analysis.bif.zeek 54 54

   :Type: :zeek:type:`function` (tag: :zeek:type:`Files::Tag`) : :zeek:type:`string`

   :zeek:see:`Files::analyzer_name`.

.. zeek:id:: Files::__disable_analyzer
   :source-code: base/bif/file_analysis.bif.zeek 34 34

   :Type: :zeek:type:`function` (tag: :zeek:type:`Files::Tag`) : :zeek:type:`bool`

   :zeek:see:`Files::disable_analyzer`.

.. zeek:id:: Files::__disable_reassembly
   :source-code: base/bif/file_analysis.bif.zeek 22 22

   :Type: :zeek:type:`function` (file_id: :zeek:type:`string`) : :zeek:type:`bool`

   :zeek:see:`Files::disable_reassembly`.

.. zeek:id:: Files::__enable_analyzer
   :source-code: base/bif/file_analysis.bif.zeek 30 30

   :Type: :zeek:type:`function` (tag: :zeek:type:`Files::Tag`) : :zeek:type:`bool`

   :zeek:see:`Files::enable_analyzer`.

.. zeek:id:: Files::__enable_reassembly
   :source-code: base/bif/file_analysis.bif.zeek 18 18

   :Type: :zeek:type:`function` (file_id: :zeek:type:`string`) : :zeek:type:`bool`

   :zeek:see:`Files::enable_reassembly`.

.. zeek:id:: Files::__file_exists
   :source-code: base/bif/file_analysis.bif.zeek 58 58

   :Type: :zeek:type:`function` (fuid: :zeek:type:`string`) : :zeek:type:`bool`

   :zeek:see:`Files::file_exists`.

.. zeek:id:: Files::__lookup_file
   :source-code: base/bif/file_analysis.bif.zeek 62 62

   :Type: :zeek:type:`function` (fuid: :zeek:type:`string`) : :zeek:type:`fa_file`

   :zeek:see:`Files::lookup_file`.

.. zeek:id:: Files::__remove_analyzer
   :source-code: base/bif/file_analysis.bif.zeek 46 46

   :Type: :zeek:type:`function` (file_id: :zeek:type:`string`, tag: :zeek:type:`Files::Tag`, args: :zeek:type:`any`) : :zeek:type:`bool`

   :zeek:see:`Files::remove_analyzer`.

.. zeek:id:: Files::__set_reassembly_buffer
   :source-code: base/bif/file_analysis.bif.zeek 26 26

   :Type: :zeek:type:`function` (file_id: :zeek:type:`string`, max: :zeek:type:`count`) : :zeek:type:`bool`

   :zeek:see:`Files::set_reassembly_buffer_size`.

.. zeek:id:: Files::__set_timeout_interval
   :source-code: base/bif/file_analysis.bif.zeek 14 14

   :Type: :zeek:type:`function` (file_id: :zeek:type:`string`, t: :zeek:type:`interval`) : :zeek:type:`bool`

   :zeek:see:`Files::set_timeout_interval`.

.. zeek:id:: Files::__stop
   :source-code: base/bif/file_analysis.bif.zeek 50 50

   :Type: :zeek:type:`function` (file_id: :zeek:type:`string`) : :zeek:type:`bool`

   :zeek:see:`Files::stop`.

.. zeek:id:: set_file_handle
   :source-code: base/bif/file_analysis.bif.zeek 76 76

   :Type: :zeek:type:`function` (handle: :zeek:type:`string`) : :zeek:type:`any`

   For use within a :zeek:see:`get_file_handle` handler to set a unique
   identifier to associate with the current input to the file analysis
   framework.  Using an empty string for the handle signifies that the
   input will be ignored/discarded.
   

   :param handle: A string that uniquely identifies a file.
   
   .. zeek:see:: get_file_handle


