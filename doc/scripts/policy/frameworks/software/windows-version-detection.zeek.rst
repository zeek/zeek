:tocdepth: 3

policy/frameworks/software/windows-version-detection.zeek
=========================================================
.. zeek:namespace:: OS

Windows systems access a Microsoft Certificate Revocation List (CRL) periodically. The
user agent for these requests reveals which version of Crypt32.dll installed on the system,
which can uniquely identify the version of Windows that's running.

This script will log the version of Windows that was identified to the Software framework.

:Namespace: OS
:Imports: :doc:`base/frameworks/software </scripts/base/frameworks/software/index>`, :doc:`base/protocols/http </scripts/base/protocols/http/index>`

Summary
~~~~~~~
Redefinable Options
###################
========================================================================= =
:zeek:id:`OS::crypto_api_mapping`: :zeek:type:`table` :zeek:attr:`&redef` 
========================================================================= =

Types
#####
============================================================ =
:zeek:type:`Software::name_and_version`: :zeek:type:`record` 
============================================================ =

Redefinitions
#############
============================================== ==================================================
:zeek:type:`Software::Type`: :zeek:type:`enum` 
                                               
                                               * :zeek:enum:`OS::WINDOWS`:
                                                 Identifier for Windows operating system versions
============================================== ==================================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Redefinable Options
###################
.. zeek:id:: OS::crypto_api_mapping
   :source-code: policy/frameworks/software/windows-version-detection.zeek 23 23

   :Type: :zeek:type:`table` [:zeek:type:`string`] of :zeek:type:`Software::name_and_version`
   :Attributes: :zeek:attr:`&redef`
   :Default:

      ::

         {
            ["Microsoft-CryptoAPI/5.131.3790.1830"] = [name="Windows", version=[major=5, minor=131, minor2=3790, minor3=1830, addl="XP x64 or Server 2003 SP1"]],
            ["Microsoft-CryptoAPI/5.131.2600.3249"] = [name="Windows", version=[major=5, minor=131, minor2=2600, minor3=3249, addl="XP SP3 RC Beta"]],
            ["Microsoft-CryptoAPI/5.131.2600.5508"] = [name="Windows", version=[major=5, minor=131, minor2=2600, minor3=5508, addl="XP SP3 RC2 Update 2"]],
            ["Microsoft-CryptoAPI/5.131.2600.3180"] = [name="Windows", version=[major=5, minor=131, minor2=2600, minor3=3180, addl="XP SP3 Beta 1"]],
            ["Microsoft-CryptoAPI/5.131.2600.3264"] = [name="Windows", version=[major=5, minor=131, minor2=2600, minor3=3264, addl="XP SP3 RC1"]],
            ["Microsoft-CryptoAPI/6.2"] = [name="Windows", version=[major=6, minor=2, minor2=<uninitialized>, minor3=<uninitialized>, addl="8 or Server 2012"]],
            ["Microsoft-CryptoAPI/5.131.2600.3282"] = [name="Windows", version=[major=5, minor=131, minor2=2600, minor3=3282, addl="XP SP3 RC1 Update"]],
            ["Microsoft-CryptoAPI/5.131.3790.5235"] = [name="Windows", version=[major=5, minor=131, minor2=3790, minor3=5235, addl="XP x64 or Server 2003 with MS13-095"]],
            ["Microsoft-CryptoAPI/6.4"] = [name="Windows", version=[major=6, minor=4, minor2=<uninitialized>, minor3=<uninitialized>, addl="10 Technical Preview"]],
            ["Microsoft-CryptoAPI/5.131.2600.0"] = [name="Windows", version=[major=5, minor=131, minor2=2600, minor3=0, addl="XP SP0"]],
            ["Microsoft-CryptoAPI/5.131.2600.5512"] = [name="Windows", version=[major=5, minor=131, minor2=2600, minor3=5512, addl="XP SP3"]],
            ["Microsoft-CryptoAPI/5.131.2195.6661"] = [name="Windows", version=[major=5, minor=131, minor2=2195, minor3=6661, addl="2000 SP4"]],
            ["Microsoft-CryptoAPI/5.131.2195.6926"] = [name="Windows", version=[major=5, minor=131, minor2=2195, minor3=6926, addl="2000 with Hotfix 98830"]],
            ["Microsoft-CryptoAPI/6.0"] = [name="Windows", version=[major=6, minor=0, minor2=<uninitialized>, minor3=<uninitialized>, addl="Vista or Server 2008"]],
            ["Microsoft-CryptoAPI/5.131.3790.0"] = [name="Windows", version=[major=5, minor=131, minor2=3790, minor3=0, addl="XP x64 or Server 2003 SP0"]],
            ["Microsoft-CryptoAPI/6.3"] = [name="Windows", version=[major=6, minor=3, minor2=<uninitialized>, minor3=<uninitialized>, addl="8.1 or Server 2012 R2"]],
            ["Microsoft-CryptoAPI/5.131.2600.3205"] = [name="Windows", version=[major=5, minor=131, minor2=2600, minor3=3205, addl="XP SP3 Beta 2"]],
            ["Microsoft-CryptoAPI/5.131.2600.1106"] = [name="Windows", version=[major=5, minor=131, minor2=2600, minor3=1106, addl="XP SP1"]],
            ["Microsoft-CryptoAPI/5.131.2600.2180"] = [name="Windows", version=[major=5, minor=131, minor2=2600, minor3=2180, addl="XP SP2"]],
            ["Microsoft-CryptoAPI/5.131.2195.6824"] = [name="Windows", version=[major=5, minor=131, minor2=2195, minor3=6824, addl="2000 with MS04-11"]],
            ["Microsoft-CryptoAPI/5.131.2600.3300"] = [name="Windows", version=[major=5, minor=131, minor2=2600, minor3=3300, addl="XP SP3 RC2"]],
            ["Microsoft-CryptoAPI/6.1"] = [name="Windows", version=[major=6, minor=1, minor2=<uninitialized>, minor3=<uninitialized>, addl="7 or Server 2008 R2"]],
            ["Microsoft-CryptoAPI/10.0"] = [name="Windows", version=[major=10, minor=0, minor2=<uninitialized>, minor3=<uninitialized>, addl=<uninitialized>]],
            ["Microsoft-CryptoAPI/5.131.2600.3311"] = [name="Windows", version=[major=5, minor=131, minor2=2600, minor3=3311, addl="XP SP3 RC2 Update"]],
            ["Microsoft-CryptoAPI/5.131.3790.3959"] = [name="Windows", version=[major=5, minor=131, minor2=3790, minor3=3959, addl="XP x64 or Server 2003 SP2"]]
         }



Types
#####
.. zeek:type:: Software::name_and_version
   :source-code: policy/frameworks/software/windows-version-detection.zeek 18 21

   :Type: :zeek:type:`record`

      name: :zeek:type:`string`

      version: :zeek:type:`Software::Version`



