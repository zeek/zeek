.. _setup:

#######
 Setup
#######

This tutorial will use Zeek's latest docker image: ``zeek/zeek``. You
can see :doc:`installing Zeek </install>` for how to retrieve that
image. Then, execute bash inside of it:

.. code:: console

   $ docker run -it zeek/zeek

Next, change into the ``/opt`` directory and clone the tutorial
repository from Git:

.. code:: console

   root@xxxxxxxxxxxx:/# cd /opt
   root@xxxxxxxxxxxx:/opt# git clone https://gist.github.com/evantypanski/74028fdd045d31b6feb440ad31fb3499 zeek-tutorial-setup
   root@xxxxxxxxxxxx:/opt# cd zeek-tutorial-setup

TODO: This should be in a repo in the Zeek tree, I think.

Now, run the provided setup script after giving it executable
permissions:

.. code:: console

   root@xxxxxxxxxxxx:/opt/zeek-tutorial-setup# chmod +x ./setup.sh
   root@xxxxxxxxxxxx:/opt/zeek-tutorial-setup# ./setup.sh

Once that completes, you should be in ``/opt/zeek-tutorial-setup`` with
the setup script ran. You can look in ``zeek/`` to find the Zeek source
code, ``traces/`` to find a collection of sample traces, and
``scripts/`` to find some scripts used throughout the tutorial. Feel
free to use those as a playground during some of the upcoming exercises.

Now, ensure that you can properly run Zeek on the pcap file from the
quickstart:

.. code:: console

   root@zeek-tutorial:/opt/zeek-tutorial-setup $ mkdir scratch
   root@zeek-tutorial:/opt/zeek-tutorial-setup $ zeek -r traces/zeek-doc/quickstart.pcap Log::default_logdir=scratch
   root@zeek-tutorial:/opt/zeek-tutorial-setup $ ls scratch
   conn.log  files.log  http.log  packet_filter.log  weird.log

If you get a few log files, then it properly read the quickstart pcap.
You’re now set up to do the tutorial :)
