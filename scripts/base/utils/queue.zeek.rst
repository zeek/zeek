:tocdepth: 3

base/utils/queue.zeek
=====================
.. bro:namespace:: Queue

A FIFO queue.

:Namespace: Queue

Summary
~~~~~~~
Types
#####
=============================================== ==========================================
:bro:type:`Queue::Queue`: :bro:type:`record`    The internal data structure for the queue.
:bro:type:`Queue::Settings`: :bro:type:`record` Settings for initializing the queue.
=============================================== ==========================================

Redefinitions
#############
============================================ =
:bro:type:`Queue::Queue`: :bro:type:`record` 
============================================ =

Functions
#########
================================================= ==============================================================
:bro:id:`Queue::get`: :bro:type:`function`        Get a value from the end of a queue.
:bro:id:`Queue::get_vector`: :bro:type:`function` Get the contents of the queue as a vector.
:bro:id:`Queue::init`: :bro:type:`function`       Initialize a queue record structure.
:bro:id:`Queue::len`: :bro:type:`function`        Get the number of items in a queue.
:bro:id:`Queue::merge`: :bro:type:`function`      Merge two queues together.
:bro:id:`Queue::peek`: :bro:type:`function`       Peek at the value at the end of the queue without removing it.
:bro:id:`Queue::put`: :bro:type:`function`        Put a value onto the beginning of a queue.
================================================= ==============================================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Types
#####
.. bro:type:: Queue::Queue

   :Type: :bro:type:`record`

      initialized: :bro:type:`bool` :bro:attr:`&default` = ``F`` :bro:attr:`&optional`

      vals: :bro:type:`table` [:bro:type:`count`] of :bro:type:`any` :bro:attr:`&optional`

      settings: :bro:type:`Queue::Settings` :bro:attr:`&optional`

      top: :bro:type:`count` :bro:attr:`&default` = ``0`` :bro:attr:`&optional`

      bottom: :bro:type:`count` :bro:attr:`&default` = ``0`` :bro:attr:`&optional`

      size: :bro:type:`count` :bro:attr:`&default` = ``0`` :bro:attr:`&optional`

   The internal data structure for the queue.

.. bro:type:: Queue::Settings

   :Type: :bro:type:`record`

      max_len: :bro:type:`count` :bro:attr:`&optional`
         If a maximum length is set for the queue
         it will maintain itself at that
         maximum length automatically.

   Settings for initializing the queue.

Functions
#########
.. bro:id:: Queue::get

   :Type: :bro:type:`function` (q: :bro:type:`Queue::Queue`) : :bro:type:`any`

   Get a value from the end of a queue.
   

   :q: The queue to get the value from.
   

   :returns: The value gotten from the queue.

.. bro:id:: Queue::get_vector

   :Type: :bro:type:`function` (q: :bro:type:`Queue::Queue`, ret: :bro:type:`vector` of :bro:type:`any`) : :bro:type:`void`

   Get the contents of the queue as a vector.
   

   :q: The queue.
   

   :ret: A vector containing the current contents of the queue
        as the type of ret.

.. bro:id:: Queue::init

   :Type: :bro:type:`function` (s: :bro:type:`Queue::Settings` :bro:attr:`&default` = ``[]`` :bro:attr:`&optional`) : :bro:type:`Queue::Queue`

   Initialize a queue record structure.
   

   :s: A record which configures the queue.
   

   :returns: An opaque queue record.

.. bro:id:: Queue::len

   :Type: :bro:type:`function` (q: :bro:type:`Queue::Queue`) : :bro:type:`count`

   Get the number of items in a queue.
   

   :q: The queue.
   

   :returns: The length of the queue.

.. bro:id:: Queue::merge

   :Type: :bro:type:`function` (q1: :bro:type:`Queue::Queue`, q2: :bro:type:`Queue::Queue`) : :bro:type:`Queue::Queue`

   Merge two queues together.  If any settings are applied
   to the queues, the settings from *q1* are used for the new
   merged queue.
   

   :q1: The first queue.  Settings are taken from here.
   

   :q2: The second queue.
   

   :returns: A new queue from merging the other two together.

.. bro:id:: Queue::peek

   :Type: :bro:type:`function` (q: :bro:type:`Queue::Queue`) : :bro:type:`any`

   Peek at the value at the end of the queue without removing it.
   

   :q: The queue to get the value from.
   

   :returns: The value at the end of the queue.

.. bro:id:: Queue::put

   :Type: :bro:type:`function` (q: :bro:type:`Queue::Queue`, val: :bro:type:`any`) : :bro:type:`void`

   Put a value onto the beginning of a queue.
   

   :q: The queue to put the value into.
   

   :val: The value to insert into the queue.


