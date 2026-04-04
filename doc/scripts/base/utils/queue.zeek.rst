:tocdepth: 3

base/utils/queue.zeek
=====================
.. zeek:namespace:: Queue

A FIFO queue.

:Namespace: Queue

Summary
~~~~~~~
Types
#####
================================================= ==========================================
:zeek:type:`Queue::Queue`: :zeek:type:`record`    The internal data structure for the queue.
:zeek:type:`Queue::Settings`: :zeek:type:`record` Settings for initializing the queue.
================================================= ==========================================

Redefinitions
#############
============================================== ==========================================================================================
:zeek:type:`Queue::Queue`: :zeek:type:`record`

                                               :New Fields: :zeek:type:`Queue::Queue`

                                                 initialized: :zeek:type:`bool` :zeek:attr:`&default` = ``F`` :zeek:attr:`&optional`

                                                 vals: :zeek:type:`table` [:zeek:type:`count`] of :zeek:type:`any` :zeek:attr:`&optional`

                                                 settings: :zeek:type:`Queue::Settings` :zeek:attr:`&optional`

                                                 top: :zeek:type:`count` :zeek:attr:`&default` = ``0`` :zeek:attr:`&optional`

                                                 bottom: :zeek:type:`count` :zeek:attr:`&default` = ``0`` :zeek:attr:`&optional`

                                                 size: :zeek:type:`count` :zeek:attr:`&default` = ``0`` :zeek:attr:`&optional`
============================================== ==========================================================================================

Functions
#########
=================================================== ==============================================================
:zeek:id:`Queue::get`: :zeek:type:`function`        Get a value from the end of a queue.
:zeek:id:`Queue::get_vector`: :zeek:type:`function` Get the contents of the queue as a vector.
:zeek:id:`Queue::init`: :zeek:type:`function`       Initialize a queue record structure.
:zeek:id:`Queue::len`: :zeek:type:`function`        Get the number of items in a queue.
:zeek:id:`Queue::merge`: :zeek:type:`function`      Merge two queues together.
:zeek:id:`Queue::peek`: :zeek:type:`function`       Peek at the value at the end of the queue without removing it.
:zeek:id:`Queue::put`: :zeek:type:`function`        Put a value onto the beginning of a queue.
=================================================== ==============================================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Types
#####
.. zeek:type:: Queue::Queue
   :source-code: base/utils/queue.zeek 15 16

   :Type: :zeek:type:`record`


   .. zeek:field:: initialized :zeek:type:`bool` :zeek:attr:`&default` = ``F`` :zeek:attr:`&optional`


   .. zeek:field:: vals :zeek:type:`table` [:zeek:type:`count`] of :zeek:type:`any` :zeek:attr:`&optional`


   .. zeek:field:: settings :zeek:type:`Queue::Settings` :zeek:attr:`&optional`


   .. zeek:field:: top :zeek:type:`count` :zeek:attr:`&default` = ``0`` :zeek:attr:`&optional`


   .. zeek:field:: bottom :zeek:type:`count` :zeek:attr:`&default` = ``0`` :zeek:attr:`&optional`


   .. zeek:field:: size :zeek:type:`count` :zeek:attr:`&default` = ``0`` :zeek:attr:`&optional`


   The internal data structure for the queue.

.. zeek:type:: Queue::Settings
   :source-code: base/utils/queue.zeek 7 12

   :Type: :zeek:type:`record`


   .. zeek:field:: max_len :zeek:type:`count` :zeek:attr:`&optional`

      If a maximum length is set for the queue
      it will maintain itself at that
      maximum length automatically.


   Settings for initializing the queue.

Functions
#########
.. zeek:id:: Queue::get
   :source-code: base/utils/queue.zeek 105 111

   :Type: :zeek:type:`function` (q: :zeek:type:`Queue::Queue`) : :zeek:type:`any`

   Get a value from the end of a queue.


   :param q: The queue to get the value from.


   :returns: The value gotten from the queue.

.. zeek:id:: Queue::get_vector
   :source-code: base/utils/queue.zeek 140 155

   :Type: :zeek:type:`function` (q: :zeek:type:`Queue::Queue`, ret: :zeek:type:`vector` of :zeek:type:`any`) : :zeek:type:`void`

   Get the contents of the queue as a vector.


   :param q: The queue.


   :param ret: A vector containing the current contents of the queue
        as the type of ret.

.. zeek:id:: Queue::init
   :source-code: base/utils/queue.zeek 88 95

   :Type: :zeek:type:`function` (s: :zeek:type:`Queue::Settings` :zeek:attr:`&default` = ``[]`` :zeek:attr:`&optional`) : :zeek:type:`Queue::Queue`

   Initialize a queue record structure.


   :param s: A record which configures the queue.


   :returns: An opaque queue record.

.. zeek:id:: Queue::len
   :source-code: base/utils/queue.zeek 135 138

   :Type: :zeek:type:`function` (q: :zeek:type:`Queue::Queue`) : :zeek:type:`count`

   Get the number of items in a queue.


   :param q: The queue.


   :returns: The length of the queue.

.. zeek:id:: Queue::merge
   :source-code: base/utils/queue.zeek 118 133

   :Type: :zeek:type:`function` (q1: :zeek:type:`Queue::Queue`, q2: :zeek:type:`Queue::Queue`) : :zeek:type:`Queue::Queue`

   Merge two queues together.  If any settings are applied
   to the queues, the settings from *q1* are used for the new
   merged queue.


   :param q1: The first queue.  Settings are taken from here.


   :param q2: The second queue.


   :returns: A new queue from merging the other two together.

.. zeek:id:: Queue::peek
   :source-code: base/utils/queue.zeek 113 116

   :Type: :zeek:type:`function` (q: :zeek:type:`Queue::Queue`) : :zeek:type:`any`

   Peek at the value at the end of the queue without removing it.


   :param q: The queue to get the value from.


   :returns: The value at the end of the queue.

.. zeek:id:: Queue::put
   :source-code: base/utils/queue.zeek 97 103

   :Type: :zeek:type:`function` (q: :zeek:type:`Queue::Queue`, val: :zeek:type:`any`) : :zeek:type:`void`

   Put a value onto the beginning of a queue.


   :param q: The queue to put the value into.


   :param val: The value to insert into the queue.


