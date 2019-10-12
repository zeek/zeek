:tocdepth: 3

base/files/pe/consts.zeek
=========================
.. zeek:namespace:: PE


:Namespace: PE

Summary
~~~~~~~
Constants
#########
======================================================================================================== =
:zeek:id:`PE::directories`: :zeek:type:`table` :zeek:attr:`&default` = :zeek:type:`function`             
:zeek:id:`PE::dll_characteristics`: :zeek:type:`table` :zeek:attr:`&default` = :zeek:type:`function`     
:zeek:id:`PE::file_characteristics`: :zeek:type:`table` :zeek:attr:`&default` = :zeek:type:`function`    
:zeek:id:`PE::machine_types`: :zeek:type:`table` :zeek:attr:`&default` = :zeek:type:`function`           
:zeek:id:`PE::os_versions`: :zeek:type:`table` :zeek:attr:`&default` = :zeek:type:`function`             
:zeek:id:`PE::section_characteristics`: :zeek:type:`table` :zeek:attr:`&default` = :zeek:type:`function` 
:zeek:id:`PE::section_descs`: :zeek:type:`table` :zeek:attr:`&default` = :zeek:type:`function`           
:zeek:id:`PE::windows_subsystems`: :zeek:type:`table` :zeek:attr:`&default` = :zeek:type:`function`      
======================================================================================================== =


Detailed Interface
~~~~~~~~~~~~~~~~~~
Constants
#########
.. zeek:id:: PE::directories

   :Type: :zeek:type:`table` [:zeek:type:`count`] of :zeek:type:`string`
   :Attributes: :zeek:attr:`&default` = :zeek:type:`function`
   :Default:

      ::

         {
            [2] = "Resource Table",
            [9] = "TLS Table",
            [6] = "Debug",
            [11] = "Bound Import",
            [14] = "CLR Runtime Header",
            [4] = "Certificate Table",
            [1] = "Import Table",
            [8] = "Global Ptr",
            [7] = "Architecture",
            [15] = "Reserved",
            [5] = "Base Relocation Table",
            [10] = "Load Config Table",
            [0] = "Export Table",
            [3] = "Exception Table",
            [12] = "IAT",
            [13] = "Delay Import Descriptor"
         }



.. zeek:id:: PE::dll_characteristics

   :Type: :zeek:type:`table` [:zeek:type:`count`] of :zeek:type:`string`
   :Attributes: :zeek:attr:`&default` = :zeek:type:`function`
   :Default:

      ::

         {
            [256] = "NX_COMPAT",
            [512] = "NO_ISOLATION",
            [128] = "FORCE_INTEGRITY",
            [2048] = "NO_BIND",
            [32768] = "TERMINAL_SERVER_AWARE",
            [8192] = "WDM_DRIVER",
            [1024] = "NO_SEH",
            [64] = "DYNAMIC_BASE"
         }



.. zeek:id:: PE::file_characteristics

   :Type: :zeek:type:`table` [:zeek:type:`count`] of :zeek:type:`string`
   :Attributes: :zeek:attr:`&default` = :zeek:type:`function`
   :Default:

      ::

         {
            [2] = "EXECUTABLE_IMAGE",
            [4] = "LINE_NUMS_STRIPPED",
            [256] = "32BIT_MACHINE",
            [512] = "DEBUG_STRIPPED",
            [1] = "RELOCS_STRIPPED",
            [8] = "LOCAL_SYMS_STRIPPED",
            [16384] = "UP_SYSTEM_ONLY",
            [32] = "LARGE_ADDRESS_AWARE",
            [128] = "BYTES_REVERSED_LO",
            [2048] = "NET_RUN_FROM_SWAP",
            [32768] = "BYTES_REVERSED_HI",
            [8192] = "DLL",
            [1024] = "REMOVABLE_RUN_FROM_SWAP",
            [4096] = "SYSTEM",
            [16] = "AGGRESSIVE_WS_TRIM"
         }



.. zeek:id:: PE::machine_types

   :Type: :zeek:type:`table` [:zeek:type:`count`] of :zeek:type:`string`
   :Attributes: :zeek:attr:`&default` = :zeek:type:`function`
   :Default:

      ::

         {
            [496] = "POWERPC",
            [870] = "MIPSFPU",
            [497] = "POWERPCFP",
            [450] = "THUMB",
            [512] = "IA64",
            [422] = "SH4",
            [361] = "WCEMIPSV2",
            [3772] = "EBC",
            [34404] = "AMD64",
            [452] = "ARMNT",
            [358] = "R4000",
            [448] = "ARM",
            [467] = "AM33",
            [43620] = "ARM64",
            [36929] = "M32R",
            [332] = "I386",
            [418] = "SH3",
            [0] = "UNKNOWN",
            [1126] = "MIPSFPU16",
            [424] = "SH5",
            [419] = "SH3DSP",
            [614] = "MIPS16"
         }



.. zeek:id:: PE::os_versions

   :Type: :zeek:type:`table` [:zeek:type:`count`, :zeek:type:`count`] of :zeek:type:`string`
   :Attributes: :zeek:attr:`&default` = :zeek:type:`function`
   :Default:

      ::

         {
            [6, 0] = "Windows Vista or Server 2008",
            [5, 0] = "Windows 2000",
            [6, 1] = "Windows 7 or Server 2008 R2",
            [6, 3] = "Windows 8.1 or Server 2012 R2",
            [3, 50] = "Windows NT 3.5",
            [2, 11] = "Windows 2.11",
            [1, 4] = "Windows 1.04",
            [1, 0] = "Windows 1.0",
            [3, 10] = "Windows 3.1 or NT 3.1",
            [2, 10] = "Windows 2.10",
            [4, 90] = "Windows Me",
            [3, 2] = "Windows 3.2",
            [2, 0] = "Windows 2.0",
            [4, 10] = "Windows 98",
            [3, 51] = "Windows NT 3.51",
            [1, 1] = "Windows 1.01",
            [5, 1] = "Windows XP",
            [10, 0] = "Windows 10",
            [3, 0] = "Windows 3.0",
            [6, 4] = "Windows 10 Technical Preview",
            [6, 2] = "Windows 8 or Server 2012",
            [3, 11] = "Windows for Workgroups 3.11",
            [4, 0] = "Windows 95 or NT 4.0",
            [1, 3] = "Windows 1.03",
            [5, 2] = "Windows XP x64 or Server 2003"
         }



.. zeek:id:: PE::section_characteristics

   :Type: :zeek:type:`table` [:zeek:type:`count`] of :zeek:type:`string`
   :Attributes: :zeek:attr:`&default` = :zeek:type:`function`
   :Default:

      ::

         {
            [10485760] = "ALIGN_512BYTES",
            [14680064] = "ALIGN_8192BYTES",
            [16777216] = "LNK_NRELOC_OVFL",
            [7340032] = "ALIGN_64BYTES",
            [256] = "LNK_OTHER",
            [512] = "LNK_INFO",
            [131072] = "MEM_16BIT",
            [8388608] = "ALIGN_128BYTES",
            [33554432] = "MEM_DISCARDABLE",
            [8] = "TYPE_NO_PAD",
            [12582912] = "ALIGN_2048BYTES",
            [536870912] = "MEM_EXECUTE",
            [67108864] = "MEM_NOT_CACHED",
            [524288] = "MEM_PRELOAD",
            [262144] = "MEM_LOCKED",
            [32] = "CNT_CODE",
            [128] = "CNT_UNINITIALIZED_DATA",
            [1048576] = "ALIGN_1BYTES",
            [4194304] = "ALIGN_8BYTES",
            [2048] = "LNK_REMOVE",
            [32768] = "GPREL",
            [1073741824] = "MEM_READ",
            [2097152] = "ALIGN_2BYTES",
            [9437184] = "ALIGN_256BYTES",
            [13631488] = "ALIGN_4096BYTES",
            [134217728] = "MEM_NOT_PAGED",
            [11534336] = "ALIGN_1024BYTES",
            [2147483648] = "MEM_WRITE",
            [64] = "CNT_INITIALIZED_DATA",
            [5242880] = "ALIGN_16BYTES",
            [4096] = "LNK_COMDAT",
            [268435456] = "MEM_SHARED",
            [3145728] = "ALIGN_4BYTES",
            [6291456] = "ALIGN_32BYTES"
         }



.. zeek:id:: PE::section_descs

   :Type: :zeek:type:`table` [:zeek:type:`string`] of :zeek:type:`string`
   :Attributes: :zeek:attr:`&default` = :zeek:type:`function`
   :Default:

      ::

         {
            [".debug$T"] = "Debug types",
            [".bss"] = "Uninitialized data",
            [".rdata"] = "Read-only initialized data",
            [".debug$S"] = "Debug symbols",
            [".idlsym"] = "Includes registered SEH to support IDL attributes",
            [".tls$"] = "Thread-local storage",
            [".sdata"] = "GP-relative initialized data",
            [".xdata"] = "Exception information",
            [".reloc"] = "Image relocations",
            [".srdata"] = "GP-relative read-only data",
            [".edata"] = "Export tables",
            [".tls"] = "Thread-local storage",
            [".pdata"] = "Exception information",
            [".debug$F"] = "Generated FPO debug information",
            [".drective"] = "Linker options",
            [".sbss"] = "GP-relative uninitialized data",
            [".idata"] = "Import tables",
            [".sxdata"] = "Registered exception handler data",
            [".text"] = "Executable code",
            [".vsdata"] = "GP-relative initialized data",
            [".debug$P"] = "Precompiled debug types",
            [".rsrc"] = "Resource directory",
            [".cormeta"] = "CLR metadata that indicates that the object file contains managed code",
            [".data"] = "Initialized data"
         }



.. zeek:id:: PE::windows_subsystems

   :Type: :zeek:type:`table` [:zeek:type:`count`] of :zeek:type:`string`
   :Attributes: :zeek:attr:`&default` = :zeek:type:`function`
   :Default:

      ::

         {
            [2] = "WINDOWS_GUI",
            [9] = "WINDOWS_CE_GUI",
            [11] = "EFI_BOOT_SERVICE_DRIVER",
            [14] = "XBOX",
            [1] = "NATIVE",
            [7] = "POSIX_CUI",
            [10] = "EFI_APPLICATION",
            [0] = "UNKNOWN",
            [3] = "WINDOWS_CUI",
            [12] = "EFI_RUNTIME_DRIVER",
            [13] = "EFI_ROM"
         }




