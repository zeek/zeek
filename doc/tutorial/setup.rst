.. _setup:

#######
 Setup
#######

This tutorial will use Zeek's latest docker image: ``zeek/zeek``. You
can see :doc:`installing Zeek </install>` for how to retrieve that
image. Then, execute bash inside of it:

.. note::

   Throughout this tutorial, we will use console prompts to show
   what you execute. This first command is called from the host to
   get into the docker container. Almost all of the remaining console
   prompts are meant to be executed within the docker container as root.
   The root prompt (within the container) is ``#``, whereas the user
   prompt (outside of the container) is ``$``.

.. code:: console

   $ docker run --name "zeek-tutorial" -it zeek/zeek

Next, clone the ``zeek-training`` git repository into ``/opt``:

.. code:: console

   # git clone https://github.com/zeek/zeek-training.git /opt/zeek-training -b topic/etyp/new-setup-script && cd /opt/zeek-training/

Now, run the provided setup script:

.. code:: console

   # ./setup.sh tutorial

Once that completes, you should be in ``/opt/zeek-training`` with
the setup script ran. You can look in ``zeek/`` to find the Zeek source
code, ``traces/`` to find a collection of sample traces, and
``scripts/`` to find some scripts used throughout the tutorial. Feel
free to use those as a playground during some of the upcoming exercises.

Now, ensure that you can properly run Zeek on the pcap file from the
quickstart:

.. code:: console

   # mkdir scratch && cd scratch
   # zeek -r traces/zeek-doc/quickstart.pcap Log::default_logdir=scratch
   # ls
   conn.log  files.log  http.log  packet_filter.log  weird.log
   # cd ..

If you get a few log files, then it properly read the quickstart pcap.
You’re now set up to do the tutorial!
