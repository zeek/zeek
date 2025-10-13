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
   :source-code: base/files/pe/consts.zeek 73 73

   :Type: :zeek:type:`table` [:zeek:type:`count`] of :zeek:type:`string`
   :Attributes: :zeek:attr:`&default` = :zeek:type:`function`
   :Default:

      ::

         {
            [2] = "Resource Table",
            [14] = "CLR Runtime Header",
            [15] = "Reserved",
            [6] = "Debug",
            [8] = "Global Ptr",
            [9] = "TLS Table",
            [1] = "Import Table",
            [11] = "Bound Import",
            [7] = "Architecture",
            [5] = "Base Relocation Table",
            [10] = "Load Config Table",
            [4] = "Certificate Table",
            [13] = "Delay Import Descriptor",
            [12] = "IAT",
            [3] = "Exception Table",
            [0] = "Export Table"
         }



.. zeek:id:: PE::dll_characteristics
   :source-code: base/files/pe/consts.zeek 48 48

   :Type: :zeek:type:`table` [:zeek:type:`count`] of :zeek:type:`string`
   :Attributes: :zeek:attr:`&default` = :zeek:type:`function`
   :Default:

      ::

         {
            [512] = "NO_ISOLATION",
            [8192] = "WDM_DRIVER",
            [32768] = "TERMINAL_SERVER_AWARE",
            [64] = "DYNAMIC_BASE",
            [1024] = "NO_SEH",
            [2048] = "NO_BIND",
            [256] = "NX_COMPAT",
            [128] = "FORCE_INTEGRITY"
         }



.. zeek:id:: PE::file_characteristics
   :source-code: base/files/pe/consts.zeek 30 30

   :Type: :zeek:type:`table` [:zeek:type:`count`] of :zeek:type:`string`
   :Attributes: :zeek:attr:`&default` = :zeek:type:`function`
   :Default:

      ::

         {
            [32768] = "BYTES_REVERSED_HI",
            [2] = "EXECUTABLE_IMAGE",
            [16384] = "UP_SYSTEM_ONLY",
            [16] = "AGGRESSIVE_WS_TRIM",
            [4] = "LINE_NUMS_STRIPPED",
            [256] = "32BIT_MACHINE",
            [4096] = "SYSTEM",
            [128] = "BYTES_REVERSED_LO",
            [32] = "LARGE_ADDRESS_AWARE",
            [512] = "DEBUG_STRIPPED",
            [8192] = "DLL",
            [8] = "LOCAL_SYMS_STRIPPED",
            [1024] = "REMOVABLE_RUN_FROM_SWAP",
            [2048] = "NET_RUN_FROM_SWAP",
            [1] = "RELOCS_STRIPPED"
         }



.. zeek:id:: PE::machine_types
   :source-code: base/files/pe/consts.zeek 5 5

   :Type: :zeek:type:`table` [:zeek:type:`count`] of :zeek:type:`string`
   :Attributes: :zeek:attr:`&default` = :zeek:type:`function`
   :Default:

      ::

         {
            [332] = "I386",
            [448] = "ARM",
            [419] = "SH3DSP",
            [34404] = "AMD64",
            [1126] = "MIPSFPU16",
            [36929] = "M32R",
            [512] = "IA64",
            [424] = "SH5",
            [870] = "MIPSFPU",
            [496] = "POWERPC",
            [450] = "THUMB",
            [422] = "SH4",
            [3772] = "EBC",
            [467] = "AM33",
            [452] = "ARMNT",
            [614] = "MIPS16",
            [497] = "POWERPCFP",
            [358] = "R4000",
            [418] = "SH3",
            [0] = "UNKNOWN",
            [361] = "WCEMIPSV2",
            [43620] = "ARM64"
         }



.. zeek:id:: PE::os_versions
   :source-code: base/files/pe/consts.zeek 129 129

   :Type: :zeek:type:`table` [:zeek:type:`count`, :zeek:type:`count`] of :zeek:type:`string`
   :Attributes: :zeek:attr:`&default` = :zeek:type:`function`
   :Default:

      ::

         {
            [2, 11] = "Windows 2.11",
            [6, 2] = "Windows 8 or Server 2012",
            [5, 0] = "Windows 2000",
            [3, 51] = "Windows NT 3.51",
            [2, 0] = "Windows 2.0",
            [3, 11] = "Windows for Workgroups 3.11",
            [5, 1] = "Windows XP",
            [3, 0] = "Windows 3.0",
            [1, 0] = "Windows 1.0",
            [10, 0] = "Windows 10",
            [4, 90] = "Windows Me",
            [5, 2] = "Windows XP x64 or Server 2003",
            [6, 1] = "Windows 7 or Server 2008 R2",
            [3, 50] = "Windows NT 3.5",
            [4, 10] = "Windows 98",
            [2, 10] = "Windows 2.10",
            [1, 1] = "Windows 1.01",
            [1, 4] = "Windows 1.04",
            [6, 3] = "Windows 8.1 or Server 2012 R2",
            [6, 0] = "Windows Vista or Server 2008",
            [3, 10] = "Windows 3.1 or NT 3.1",
            [6, 4] = "Windows 10 Technical Preview",
            [3, 2] = "Windows 3.2",
            [1, 3] = "Windows 1.03",
            [4, 0] = "Windows 95 or NT 4.0"
         }



.. zeek:id:: PE::section_characteristics
   :source-code: base/files/pe/consts.zeek 92 92

   :Type: :zeek:type:`table` [:zeek:type:`count`] of :zeek:type:`string`
   :Attributes: :zeek:attr:`&default` = :zeek:type:`function`
   :Default:

      ::

         {
            [1048576] = "ALIGN_1BYTES",
            [131072] = "MEM_16BIT",
            [64] = "CNT_INITIALIZED_DATA",
            [12582912] = "ALIGN_2048BYTES",
            [8] = "TYPE_NO_PAD",
            [7340032] = "ALIGN_64BYTES",
            [13631488] = "ALIGN_4096BYTES",
            [2147483648] = "MEM_WRITE",
            [536870912] = "MEM_EXECUTE",
            [128] = "CNT_UNINITIALIZED_DATA",
            [32] = "CNT_CODE",
            [14680064] = "ALIGN_8192BYTES",
            [6291456] = "ALIGN_32BYTES",
            [4194304] = "ALIGN_8BYTES",
            [67108864] = "MEM_NOT_CACHED",
            [5242880] = "ALIGN_16BYTES",
            [32768] = "GPREL",
            [9437184] = "ALIGN_256BYTES",
            [4096] = "LNK_COMDAT",
            [524288] = "MEM_PRELOAD",
            [16777216] = "LNK_NRELOC_OVFL",
            [33554432] = "MEM_DISCARDABLE",
            [512] = "LNK_INFO",
            [11534336] = "ALIGN_1024BYTES",
            [262144] = "MEM_LOCKED",
            [3145728] = "ALIGN_4BYTES",
            [256] = "LNK_OTHER",
            [268435456] = "MEM_SHARED",
            [1073741824] = "MEM_READ",
            [2048] = "LNK_REMOVE",
            [10485760] = "ALIGN_512BYTES",
            [8388608] = "ALIGN_128BYTES",
            [2097152] = "ALIGN_2BYTES",
            [134217728] = "MEM_NOT_PAGED"
         }



.. zeek:id:: PE::section_descs
   :source-code: base/files/pe/consts.zeek 157 157

   :Type: :zeek:type:`table` [:zeek:type:`string`] of :zeek:type:`string`
   :Attributes: :zeek:attr:`&default` = :zeek:type:`function`
   :Default:

      ::

         {
            [".debug$P"] = "Precompiled debug types",
            [".drective"] = "Linker options",
            [".text"] = "Executable code",
            [".idata"] = "Import tables",
            [".sbss"] = "GP-relative uninitialized data",
            [".idlsym"] = "Includes registered SEH to support IDL attributes",
            [".edata"] = "Export tables",
            [".sdata"] = "GP-relative initialized data",
            [".rdata"] = "Read-only initialized data",
            [".pdata"] = "Exception information",
            [".debug$S"] = "Debug symbols",
            [".tls$"] = "Thread-local storage",
            [".reloc"] = "Image relocations",
            [".debug$F"] = "Generated FPO debug information",
            [".bss"] = "Uninitialized data",
            [".debug$T"] = "Debug types",
            [".cormeta"] = "CLR metadata that indicates that the object file contains managed code",
            [".tls"] = "Thread-local storage",
            [".sxdata"] = "Registered exception handler data",
            [".vsdata"] = "GP-relative initialized data",
            [".rsrc"] = "Resource directory",
            [".srdata"] = "GP-relative read-only data",
            [".data"] = "Initialized data",
            [".xdata"] = "Exception information"
         }



.. zeek:id:: PE::windows_subsystems
   :source-code: base/files/pe/consts.zeek 59 59

   :Type: :zeek:type:`table` [:zeek:type:`count`] of :zeek:type:`string`
   :Attributes: :zeek:attr:`&default` = :zeek:type:`function`
   :Default:

      ::

         {
            [2] = "WINDOWS_GUI",
            [11] = "EFI_BOOT_SERVICE_DRIVER",
            [7] = "POSIX_CUI",
            [10] = "EFI_APPLICATION",
            [14] = "XBOX",
            [13] = "EFI_ROM",
            [12] = "EFI_RUNTIME_DRIVER",
            [3] = "WINDOWS_CUI",
            [9] = "WINDOWS_CE_GUI",
            [0] = "UNKNOWN",
            [1] = "NATIVE"
         }




