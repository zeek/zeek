:tocdepth: 3

base/bif/plugins/Bro_PE.events.bif.zeek
=======================================
.. zeek:namespace:: GLOBAL


:Namespace: GLOBAL

Summary
~~~~~~~
Events
######
================================================= ===================================================================
:zeek:id:`pe_dos_code`: :zeek:type:`event`        A :abbr:`PE (Portable Executable)` file DOS stub was parsed.
:zeek:id:`pe_dos_header`: :zeek:type:`event`      A :abbr:`PE (Portable Executable)` file DOS header was parsed.
:zeek:id:`pe_file_header`: :zeek:type:`event`     A :abbr:`PE (Portable Executable)` file file header was parsed.
:zeek:id:`pe_optional_header`: :zeek:type:`event` A :abbr:`PE (Portable Executable)` file optional header was parsed.
:zeek:id:`pe_section_header`: :zeek:type:`event`  A :abbr:`PE (Portable Executable)` file section header was parsed.
================================================= ===================================================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Events
######
.. zeek:id:: pe_dos_code

   :Type: :zeek:type:`event` (f: :zeek:type:`fa_file`, code: :zeek:type:`string`)

   A :abbr:`PE (Portable Executable)` file DOS stub was parsed.
   The stub is a valid application that runs under MS-DOS, by default
   to inform the user that the program can't be run in DOS mode.
   

   :f: The file.
   

   :code: The DOS stub
   
   .. zeek:see:: pe_dos_header pe_file_header pe_optional_header pe_section_header

.. zeek:id:: pe_dos_header

   :Type: :zeek:type:`event` (f: :zeek:type:`fa_file`, h: :zeek:type:`PE::DOSHeader`)

   A :abbr:`PE (Portable Executable)` file DOS header was parsed.
   This is the top-level header and contains information like the
   size of the file, initial value of registers, etc.
   

   :f: The file.
   

   :h: The parsed DOS header information.
   
   .. zeek:see:: pe_dos_code pe_file_header pe_optional_header pe_section_header

.. zeek:id:: pe_file_header

   :Type: :zeek:type:`event` (f: :zeek:type:`fa_file`, h: :zeek:type:`PE::FileHeader`)

   A :abbr:`PE (Portable Executable)` file file header was parsed.
   This header contains information like the target machine,
   the timestamp when the file was created, the number of sections, and
   pointers to other parts of the file.
   

   :f: The file.
   

   :h: The parsed file header information.
   
   .. zeek:see:: pe_dos_header pe_dos_code pe_optional_header pe_section_header

.. zeek:id:: pe_optional_header

   :Type: :zeek:type:`event` (f: :zeek:type:`fa_file`, h: :zeek:type:`PE::OptionalHeader`)

   A :abbr:`PE (Portable Executable)` file optional header was parsed.
   This header is required for executable files, but not for object files.
   It contains information like OS requirements to execute the file, the
   original entry point address, and information needed to load the file
   into memory.
   

   :f: The file.
   

   :h: The parsed optional header information.
   
   .. zeek:see:: pe_dos_header pe_dos_code pe_file_header pe_section_header

.. zeek:id:: pe_section_header

   :Type: :zeek:type:`event` (f: :zeek:type:`fa_file`, h: :zeek:type:`PE::SectionHeader`)

   A :abbr:`PE (Portable Executable)` file section header was parsed.
   This header contains information like the section name, size, address,
   and characteristics.
   

   :f: The file.
   

   :h: The parsed section header information.
   
   .. zeek:see:: pe_dos_header pe_dos_code pe_file_header pe_optional_header


