.. _setup:

#######
 Setup
#######

This tutorial will use Zeek's latest docker image: ``zeek/zeek``. You
can see :doc:`installing Zeek </install>` for how to retrieve that
image. Then, execute bash inside of it:

.. code:: console

   $ docker run --name "zeek-tutorial" -it zeek/zeek

Next, clone the ``zeek-training`` git repository into ``/opt``:

.. code:: console

   root@xxxxxxxxxxxx:/# git clone https://github.com/zeek/zeek-training.git /opt/zeek-training -b topic/etyp/new-setup-script && cd /opt/zeek-training/

Now, run the provided setup script:

.. code:: console

   root@xxxxxxxxxxxx:/opt/zeek-training# ./setup.sh tutorial

Once that completes, you should be in ``/opt/zeek-training`` with
the setup script ran. You can look in ``zeek/`` to find the Zeek source
code, ``traces/`` to find a collection of sample traces, and
``scripts/`` to find some scripts used throughout the tutorial. Feel
free to use those as a playground during some of the upcoming exercises.

Now, ensure that you can properly run Zeek on the pcap file from the
quickstart:

.. code:: console

   root@zeek-tutorial:/opt/zeek-training $ mkdir scratch
   root@zeek-tutorial:/opt/zeek-training $ zeek -r traces/zeek-doc/quickstart.pcap Log::default_logdir=scratch
   root@zeek-tutorial:/opt/zeek-training $ ls scratch
   conn.log  files.log  http.log  packet_filter.log  weird.log

If you get a few log files, then it properly read the quickstart pcap.
You’re now set up to do the tutorial!
