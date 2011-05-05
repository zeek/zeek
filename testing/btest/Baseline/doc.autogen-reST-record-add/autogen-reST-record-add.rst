.. Automatically generated.  Do not edit.

autogen-reST-record-add.bro
===========================

:download:`Original Source File <autogen-reST-record-add.bro>`

Overview
--------


Summary
~~~~~~~
State Variables
###############
===================================== =
:bro:id:`a`: :bro:type:`my_record`

:bro:id:`b`: :bro:type:`super_record`
===================================== =

Types
#####
============================================ =
:bro:type:`my_record`: :bro:type:`record`

:bro:type:`super_record`: :bro:type:`record`
============================================ =

Functions
#########
===================================== =
:bro:id:`test_func`: :bro:type:`func`
===================================== =

Redefinitions
#############
========================================= =
:bro:type:`my_record`: :bro:type:`record`
========================================= =

Public Interface
----------------
State Variables
~~~~~~~~~~~~~~~
.. bro:id:: a

   :Type: :bro:type:`my_record`
   :Default:

   ::

      {
         field1=<uninitialized>
         field2=<uninitialized>
         field3=<uninitialized>
      }

.. bro:id:: b

   :Type: :bro:type:`super_record`
   :Default:

   ::

      {
         rec=[field1=<uninitialized>, field2=<uninitialized>, field3=<uninitialized>]
      }

Types
~~~~~
.. bro:type:: my_record

   :Type: :bro:type:`record`

      field1: :bro:type:`bool`

      field2: :bro:type:`string`

.. bro:type:: super_record

   :Type: :bro:type:`record`

      rec: :bro:type:`my_record`

Functions
~~~~~~~~~
.. bro:id:: test_func

   :Type: :bro:type:`function` () : :bro:type:`void`

Redefinitions
~~~~~~~~~~~~~
.. bro:type:: my_record

   :Type: :bro:type:`record`

      field3: :bro:type:`count` :bro:attr:`&optional`

