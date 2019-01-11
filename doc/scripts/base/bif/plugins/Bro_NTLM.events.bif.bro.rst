:tocdepth: 3

base/bif/plugins/Bro_NTLM.events.bif.bro
========================================
.. bro:namespace:: GLOBAL


:Namespace: GLOBAL

Summary
~~~~~~~
Events
######
============================================== ============================================================================
:bro:id:`ntlm_authenticate`: :bro:type:`event` Generated for :abbr:`NTLM (NT LAN Manager)` messages of type *authenticate*.
:bro:id:`ntlm_challenge`: :bro:type:`event`    Generated for :abbr:`NTLM (NT LAN Manager)` messages of type *challenge*.
:bro:id:`ntlm_negotiate`: :bro:type:`event`    Generated for :abbr:`NTLM (NT LAN Manager)` messages of type *negotiate*.
============================================== ============================================================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Events
######
.. bro:id:: ntlm_authenticate

   :Type: :bro:type:`event` (c: :bro:type:`connection`, request: :bro:type:`NTLM::Authenticate`)

   Generated for :abbr:`NTLM (NT LAN Manager)` messages of type *authenticate*.
   

   :c: The connection.
   

   :request: The parsed data of the :abbr:`NTLM (NT LAN Manager)` message. See init-bare for more details.
   
   .. bro:see:: ntlm_negotiate ntlm_challenge

.. bro:id:: ntlm_challenge

   :Type: :bro:type:`event` (c: :bro:type:`connection`, challenge: :bro:type:`NTLM::Challenge`)

   Generated for :abbr:`NTLM (NT LAN Manager)` messages of type *challenge*.
   

   :c: The connection.
   

   :negotiate: The parsed data of the :abbr:`NTLM (NT LAN Manager)` message. See init-bare for more details.
   
   .. bro:see:: ntlm_negotiate ntlm_authenticate

.. bro:id:: ntlm_negotiate

   :Type: :bro:type:`event` (c: :bro:type:`connection`, negotiate: :bro:type:`NTLM::Negotiate`)

   Generated for :abbr:`NTLM (NT LAN Manager)` messages of type *negotiate*.
   

   :c: The connection.
   

   :negotiate: The parsed data of the :abbr:`NTLM (NT LAN Manager)` message. See init-bare for more details.
   
   .. bro:see:: ntlm_challenge ntlm_authenticate


