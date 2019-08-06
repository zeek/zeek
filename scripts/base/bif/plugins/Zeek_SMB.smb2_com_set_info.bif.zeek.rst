:tocdepth: 3

base/bif/plugins/Zeek_SMB.smb2_com_set_info.bif.zeek
====================================================
.. zeek:namespace:: GLOBAL


:Namespace: GLOBAL

Summary
~~~~~~~
Events
######
======================================================== ===========================================================================================
:zeek:id:`smb2_file_allocation`: :zeek:type:`event`      Generated for :abbr:`SMB (Server Message Block)`/:abbr:`CIFS (Common Internet File System)`
                                                         version 2 requests of type *set_info* of the *allocation* subtype
:zeek:id:`smb2_file_delete`: :zeek:type:`event`          Generated for :abbr:`SMB (Server Message Block)`/:abbr:`CIFS (Common Internet File System)`
                                                         version 2 requests of type *set_info* of the *delete* subtype.
:zeek:id:`smb2_file_endoffile`: :zeek:type:`event`       Generated for :abbr:`SMB (Server Message Block)`/:abbr:`CIFS (Common Internet File System)`
                                                         version 2 requests of type *set_info* of the *end_of_file* subtype
:zeek:id:`smb2_file_fscontrol`: :zeek:type:`event`       Generated for :abbr:`SMB (Server Message Block)`/:abbr:`CIFS (Common Internet File System)`
                                                         version 2 requests of type *set_info* of the *fs_control* subtype
:zeek:id:`smb2_file_fsobjectid`: :zeek:type:`event`      Generated for :abbr:`SMB (Server Message Block)`/:abbr:`CIFS (Common Internet File System)`
                                                         version 2 requests of type *set_info* of the *fs_object_id* subtype
:zeek:id:`smb2_file_fullea`: :zeek:type:`event`          Generated for :abbr:`SMB (Server Message Block)`/:abbr:`CIFS (Common Internet File System)`
                                                         version 2 requests of type *set_info* of the *full_EA* subtype
:zeek:id:`smb2_file_link`: :zeek:type:`event`            Generated for :abbr:`SMB (Server Message Block)`/:abbr:`CIFS (Common Internet File System)`
                                                         version 2 requests of type *set_info* of the *link* subtype
:zeek:id:`smb2_file_mode`: :zeek:type:`event`            Generated for :abbr:`SMB (Server Message Block)`/:abbr:`CIFS (Common Internet File System)`
                                                         version 2 requests of type *set_info* of the *mode* subtype
:zeek:id:`smb2_file_pipe`: :zeek:type:`event`            Generated for :abbr:`SMB (Server Message Block)`/:abbr:`CIFS (Common Internet File System)`
                                                         version 2 requests of type *set_info* of the *pipe* subtype
:zeek:id:`smb2_file_position`: :zeek:type:`event`        Generated for :abbr:`SMB (Server Message Block)`/:abbr:`CIFS (Common Internet File System)`
                                                         version 2 requests of type *set_info* of the *position* subtype
:zeek:id:`smb2_file_rename`: :zeek:type:`event`          Generated for :abbr:`SMB (Server Message Block)`/:abbr:`CIFS (Common Internet File System)`
                                                         version 2 requests of type *set_info* of the *rename* subtype.
:zeek:id:`smb2_file_sattr`: :zeek:type:`event`           Generated for :abbr:`SMB (Server Message Block)`/:abbr:`CIFS (Common Internet File System)`
                                                         version 2 requests of type *set_info* of the *file* subtype
:zeek:id:`smb2_file_shortname`: :zeek:type:`event`       Generated for :abbr:`SMB (Server Message Block)`/:abbr:`CIFS (Common Internet File System)`
                                                         version 2 requests of type *set_info* of the *short_name* subtype
:zeek:id:`smb2_file_validdatalength`: :zeek:type:`event` Generated for :abbr:`SMB (Server Message Block)`/:abbr:`CIFS (Common Internet File System)`
                                                         version 2 requests of type *set_info* of the *valid_data_length* subtype
======================================================== ===========================================================================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Events
######
.. zeek:id:: smb2_file_allocation

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, hdr: :zeek:type:`SMB2::Header`, file_id: :zeek:type:`SMB2::GUID`, alloc_size: :zeek:type:`int`)

   Generated for :abbr:`SMB (Server Message Block)`/:abbr:`CIFS (Common Internet File System)`
   version 2 requests of type *set_info* of the *allocation* subtype
   
   For more infomation, see MS-SMB2:2.2.39
   

   :c: The connection.
   

   :hdr: The parsed header of the :abbr:`SMB (Server Message Block)` version 2 message.
   

   :file_id: The SMB2 GUID for the file.
   

   :alloc_size: desired allocation size.
   
   .. zeek:see:: smb2_message smb2_file_delete smb2_file_sattr smb2_file_allocation smb2_file_endoffile smb2_file_mode smb2_file_pipe smb2_file_position smb2_file_shortname smb2_file_validdatalength smb2_file_fullea smb2_file_link smb2_file_fsobjectid

.. zeek:id:: smb2_file_delete

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, hdr: :zeek:type:`SMB2::Header`, file_id: :zeek:type:`SMB2::GUID`, delete_pending: :zeek:type:`bool`)

   Generated for :abbr:`SMB (Server Message Block)`/:abbr:`CIFS (Common Internet File System)`
   version 2 requests of type *set_info* of the *delete* subtype.
   
   For more information, see MS-SMB2:2.2.39
   

   :c: The connection.
   

   :hdr: The parsed header of the :abbr:`SMB (Server Message Block)` version 2 message.
   

   :file_id: The SMB2 GUID for the file.
   

   :delete_pending: A boolean value to indicate that a file should be deleted 
                   when it's closed if set to T.
   
   .. zeek:see:: smb2_message smb2_file_delete smb2_file_sattr smb2_file_allocation smb2_file_endoffile smb2_file_mode smb2_file_pipe smb2_file_position smb2_file_shortname smb2_file_validdatalength smb2_file_fullea smb2_file_link smb2_file_fsobjectid

.. zeek:id:: smb2_file_endoffile

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, hdr: :zeek:type:`SMB2::Header`, file_id: :zeek:type:`SMB2::GUID`, end_of_file: :zeek:type:`int`)

   Generated for :abbr:`SMB (Server Message Block)`/:abbr:`CIFS (Common Internet File System)`
   version 2 requests of type *set_info* of the *end_of_file* subtype
   
   For more infomation, see MS-SMB2:2.2.39
   

   :c: The connection.
   

   :hdr: The parsed header of the :abbr:`SMB (Server Message Block)` version 2 message.
   

   :file_id: The SMB2 GUID for the file.
   

   :end_of_file: the absolute new end of file position as a byte offset from the start of the file
   
   .. zeek:see:: smb2_message smb2_file_delete smb2_file_sattr smb2_file_allocation smb2_file_endoffile smb2_file_mode smb2_file_pipe smb2_file_position smb2_file_shortname smb2_file_validdatalength smb2_file_fullea smb2_file_link smb2_file_fsobjectid

.. zeek:id:: smb2_file_fscontrol

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, hdr: :zeek:type:`SMB2::Header`, file_id: :zeek:type:`SMB2::GUID`, fs_control: :zeek:type:`SMB2::Fscontrol`)

   Generated for :abbr:`SMB (Server Message Block)`/:abbr:`CIFS (Common Internet File System)`
   version 2 requests of type *set_info* of the *fs_control* subtype
   
   For more infomation, see MS-SMB2:2.2.39
   

   :c: The connection.
   

   :hdr: The parsed header of the :abbr:`SMB (Server Message Block)` version 2 message.
   

   :file_id: The SMB2 GUID for the file.
   

   :fs_control: contains fs_control info (see MS-FCC 2.5.2)
   
   .. zeek:see:: smb2_message smb2_file_delete smb2_file_sattr smb2_file_allocation smb2_file_endoffile smb2_file_mode smb2_file_pipe smb2_file_position smb2_file_shortname smb2_file_validdatalength smb2_file_fullea smb2_file_link smb2_file_fsobjectid

.. zeek:id:: smb2_file_fsobjectid

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, hdr: :zeek:type:`SMB2::Header`, file_id: :zeek:type:`SMB2::GUID`, object_id: :zeek:type:`SMB2::GUID`, extended_info: :zeek:type:`string`)

   Generated for :abbr:`SMB (Server Message Block)`/:abbr:`CIFS (Common Internet File System)`
   version 2 requests of type *set_info* of the *fs_object_id* subtype
   
   For more infomation, see MS-SMB2:2.2.39
   

   :c: The connection.
   

   :hdr: The parsed header of the :abbr:`SMB (Server Message Block)` version 2 message.
   

   :file_id: The SMB2 GUID for the file.
   

   :object_id: contains a 16-bytes GUID that identifies the file system volume (see MS-FCC 2.5.6)
   

   :extended_info: contains extended information on the file system volume
   
   .. zeek:see:: smb2_message smb2_file_delete smb2_file_sattr smb2_file_allocation smb2_file_endoffile smb2_file_mode smb2_file_pipe smb2_file_position smb2_file_shortname smb2_file_validdatalength smb2_file_fullea smb2_file_link

.. zeek:id:: smb2_file_fullea

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, hdr: :zeek:type:`SMB2::Header`, file_id: :zeek:type:`SMB2::GUID`, file_eas: :zeek:type:`SMB2::FileEAs`)

   Generated for :abbr:`SMB (Server Message Block)`/:abbr:`CIFS (Common Internet File System)`
   version 2 requests of type *set_info* of the *full_EA* subtype
   
   For more infomation, see MS-SMB2:2.2.39
   

   :c: The connection.
   

   :hdr: The parsed header of the :abbr:`SMB (Server Message Block)` version 2 message.
   

   :file_id: The SMB2 GUID for the file.
   

   :FileEAs: a vector of extended file attributes as defined in MS-FSCC:2.4.15
   
   .. zeek:see:: smb2_message smb2_file_delete smb2_file_sattr smb2_file_allocation smb2_file_endoffile smb2_file_mode smb2_file_pipe smb2_file_position smb2_file_shortname smb2_file_validdatalength smb2_file_fullea smb2_file_link smb2_file_fsobjectid

.. zeek:id:: smb2_file_link

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, hdr: :zeek:type:`SMB2::Header`, file_id: :zeek:type:`SMB2::GUID`, root_directory: :zeek:type:`count`, file_name: :zeek:type:`string`)

   Generated for :abbr:`SMB (Server Message Block)`/:abbr:`CIFS (Common Internet File System)`
   version 2 requests of type *set_info* of the *link* subtype
   
   For more infomation, see MS-SMB2:2.2.39
   

   :c: The connection.
   

   :hdr: The parsed header of the :abbr:`SMB (Server Message Block)` version 2 message.
   

   :file_id: The SMB2 GUID for the file.
   

   :root_directory: contains the file handle for the directory where the link is to be created
   

   :file_name: contains the name to be assigned to the newly created link
   
   .. zeek:see:: smb2_message smb2_file_delete smb2_file_sattr smb2_file_allocation smb2_file_endoffile smb2_file_mode smb2_file_pipe smb2_file_position smb2_file_shortname smb2_file_validdatalength smb2_file_fullea smb2_file_link smb2_file_fsobjectid

.. zeek:id:: smb2_file_mode

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, hdr: :zeek:type:`SMB2::Header`, file_id: :zeek:type:`SMB2::GUID`, mode: :zeek:type:`count`)

   Generated for :abbr:`SMB (Server Message Block)`/:abbr:`CIFS (Common Internet File System)`
   version 2 requests of type *set_info* of the *mode* subtype
   
   For more infomation, see MS-SMB2:2.2.39
   

   :c: The connection.
   

   :hdr: The parsed header of the :abbr:`SMB (Server Message Block)` version 2 message.
   

   :file_id: The SMB2 GUID for the file.
   

   :mode: specifies how the file will subsequently be accessed.
   
   .. zeek:see:: smb2_message smb2_file_delete smb2_file_sattr smb2_file_allocation smb2_file_endoffile smb2_file_mode smb2_file_pipe smb2_file_position smb2_file_shortname smb2_file_validdatalength smb2_file_fullea smb2_file_link smb2_file_fsobjectid

.. zeek:id:: smb2_file_pipe

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, hdr: :zeek:type:`SMB2::Header`, file_id: :zeek:type:`SMB2::GUID`, read_mode: :zeek:type:`count`, completion_mode: :zeek:type:`count`)

   Generated for :abbr:`SMB (Server Message Block)`/:abbr:`CIFS (Common Internet File System)`
   version 2 requests of type *set_info* of the *pipe* subtype
   
   For more infomation, see MS-SMB2:2.2.39
   

   :c: The connection.
   

   :hdr: The parsed header of the :abbr:`SMB (Server Message Block)` version 2 message.
   

   :file_id: The SMB2 GUID for the file.
   

   :read_mode: specifies if data must be read as a stream of bytes or messages
   

   :completion_mode: specifies if blocking mode must be enabled or not
   
   .. zeek:see:: smb2_message smb2_file_delete smb2_file_sattr smb2_file_allocation smb2_file_endoffile smb2_file_mode smb2_file_pipe smb2_file_position smb2_file_shortname smb2_file_validdatalength smb2_file_fullea smb2_file_link smb2_file_fsobjectid

.. zeek:id:: smb2_file_position

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, hdr: :zeek:type:`SMB2::Header`, file_id: :zeek:type:`SMB2::GUID`, current_byte_offset: :zeek:type:`int`)

   Generated for :abbr:`SMB (Server Message Block)`/:abbr:`CIFS (Common Internet File System)`
   version 2 requests of type *set_info* of the *position* subtype
   
   For more infomation, see MS-SMB2:2.2.39
   

   :c: The connection.
   

   :hdr: The parsed header of the :abbr:`SMB (Server Message Block)` version 2 message.
   

   :file_id: The SMB2 GUID for the file.
   

   :current_byte_offset: specifies the offset, in bytes, of the file pointer from the beginning of the file
   
   .. zeek:see:: smb2_message smb2_file_delete smb2_file_sattr smb2_file_allocation smb2_file_endoffile smb2_file_mode smb2_file_pipe smb2_file_position smb2_file_shortname smb2_file_validdatalength smb2_file_fullea smb2_file_link smb2_file_fsobjectid

.. zeek:id:: smb2_file_rename

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, hdr: :zeek:type:`SMB2::Header`, file_id: :zeek:type:`SMB2::GUID`, dst_filename: :zeek:type:`string`)

   Generated for :abbr:`SMB (Server Message Block)`/:abbr:`CIFS (Common Internet File System)`
   version 2 requests of type *set_info* of the *rename* subtype.
   
   For more information, see MS-SMB2:2.2.39
   

   :c: The connection.
   

   :hdr: The parsed header of the :abbr:`SMB (Server Message Block)` version 2 message.
   

   :file_id: A GUID to identify the file.
   

   :dst_filename: The filename to rename the file into.
   
   .. zeek:see:: smb2_message smb2_file_delete smb2_file_sattr smb2_file_allocation smb2_file_endoffile smb2_file_mode smb2_file_pipe smb2_file_position smb2_file_shortname smb2_file_validdatalength smb2_file_fullea smb2_file_link smb2_file_fsobjectid

.. zeek:id:: smb2_file_sattr

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, hdr: :zeek:type:`SMB2::Header`, file_id: :zeek:type:`SMB2::GUID`, times: :zeek:type:`SMB::MACTimes`, attrs: :zeek:type:`SMB2::FileAttrs`)

   Generated for :abbr:`SMB (Server Message Block)`/:abbr:`CIFS (Common Internet File System)`
   version 2 requests of type *set_info* of the *file* subtype
   
   For more infomation, see MS-SMB2:2.2.39
   

   :c: The connection.
   

   :hdr: The parsed header of the :abbr:`SMB (Server Message Block)` version 2 message.
   

   :file_id: The SMB2 GUID for the file.
   

   :times: Timestamps associated with the file in question.
   

   :attrs: File attributes.
   
   .. zeek:see:: smb2_message smb2_file_delete smb2_file_sattr smb2_file_allocation smb2_file_endoffile smb2_file_mode smb2_file_pipe smb2_file_position smb2_file_shortname smb2_file_validdatalength smb2_file_fullea smb2_file_link smb2_file_fsobjectid

.. zeek:id:: smb2_file_shortname

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, hdr: :zeek:type:`SMB2::Header`, file_id: :zeek:type:`SMB2::GUID`, file_name: :zeek:type:`string`)

   Generated for :abbr:`SMB (Server Message Block)`/:abbr:`CIFS (Common Internet File System)`
   version 2 requests of type *set_info* of the *short_name* subtype
   
   For more infomation, see MS-SMB2:2.2.39
   

   :c: The connection.
   

   :hdr: The parsed header of the :abbr:`SMB (Server Message Block)` version 2 message.
   

   :file_id: The SMB2 GUID for the file.
   

   :file_name: specifies the name of the file to be changed
   
   .. zeek:see:: smb2_message smb2_file_delete smb2_file_sattr smb2_file_allocation smb2_file_endoffile smb2_file_mode smb2_file_pipe smb2_file_position smb2_file_shortname smb2_file_validdatalength smb2_file_fullea smb2_file_link smb2_file_fsobjectid

.. zeek:id:: smb2_file_validdatalength

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, hdr: :zeek:type:`SMB2::Header`, file_id: :zeek:type:`SMB2::GUID`, valid_data_length: :zeek:type:`int`)

   Generated for :abbr:`SMB (Server Message Block)`/:abbr:`CIFS (Common Internet File System)`
   version 2 requests of type *set_info* of the *valid_data_length* subtype
   
   For more infomation, see MS-SMB2:2.2.39
   

   :c: The connection.
   

   :hdr: The parsed header of the :abbr:`SMB (Server Message Block)` version 2 message.
   

   :file_id: The SMB2 GUID for the file.
   

   :valid_data_length: specifies the new valid data length for the file
   
   .. zeek:see:: smb2_message smb2_file_delete smb2_file_sattr smb2_file_allocation smb2_file_endoffile smb2_file_mode smb2_file_pipe smb2_file_position smb2_file_shortname smb2_file_validdatalength smb2_file_fullea smb2_file_link smb2_file_fsobjectid


