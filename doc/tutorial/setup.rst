.. _setup:

#######
 Setup
#######

This tutorial will use Zeek's latest container image: ``zeek/zeek`` on
`our Docker Hub <https://hub.docker.com/u/zeek>`_.
You can refer to :ref:`Docker image installation <docker-images>` for how to
retrieve that image. Then, execute bash inside of it:

.. code:: console

   $ docker run --name "zeek-tutorial" -it zeek/zeek

.. note::

   Throughout this tutorial, we will use console prompts to show
   what you execute. This first command is called from the host to
   enter the container. Almost all of the remaining console
   prompts are meant to be executed within the container as root.
   In this tutorial, the root prompt (within the container) is ``#``,
   whereas the user prompt (outside of the container) is ``$``.

Next, clone the ``zeek-training`` git repository into ``/opt``:

.. code:: console

   # git clone https://github.com/zeek/zeek-training.git /opt/zeek-training && cd /opt/zeek-training/

You should find yourself in ``/opt/zeek-training``, in a fresh clone
of our training content.
Now run the provided setup script to prepare the tutorial's resources
and add required tooling, all inside the container:

.. code:: console

   # ./setup.sh tutorial

You can look in ``zeek/`` to find the Zeek source
code, ``traces/`` to find a collection of sample traces, and
``scripts/`` to find some scripts used throughout the tutorial. Feel
free to use those as a playground during some of the upcoming exercises.

Now, ensure that you can properly run Zeek on the pcap file from the
quickstart:

.. code:: console

   # mkdir scratch && cd scratch
   # zeek -r ../traces/zeek-doc/quickstart.pcap
   # ls
   conn.log  files.log  http.log  packet_filter.log  weird.log
   # cd ..

If you get a few log files, then Zeek properly processed the quickstart pcap.
You're now set up to do the tutorial!
