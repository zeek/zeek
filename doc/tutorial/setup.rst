.. _setup:

#######
 Setup
#######

This tutorial will use a custom Zeek docker container with some
developer tooling. This ensures that the tutorial can be the same no
matter the user’s environment. Where applicable, the tutorial may
mention how this would be used on a local Zeek install in order to
generalize the approach.

Right now the dockerfile is in a gist on my github :) I'm not opposed to
making this just a script you clone from the base Zeek image, but I also
think there's value in a simple setup for this tutorial where users just
get pcaps and nice tools. Don't care enough to argue for it if there's
pushback, though.
https://gist.github.com/evantypanski/67dfc9e6afd422996a5cfed9356d3987

TODO: Install Docker and link to the container in a real way.

Now, you can enter the Zeek tutorial container with the following
command:

   .. code:: console

      $ docker run -it zeek-tutorial:latest

This should open a Bash prompt in the ``/opt`` directory. Within the
``/opt`` directory, there are two more directories:

``/opt/zeek`` ``/opt/traces``

The ``zeek`` directory contains the Zeek source code, but not the
installed Zeek. This is simply for reference - you can find Zeek
installed in ``/usr/local/zeek``.

TODO: Should we give a tour of the installed directory here? I think
that was in the quickstart before

The ``traces`` directory contains a few useful traces to test Zeek with.
We will use these traces extensively throughout the tutorial, so you
don’t need to make your own traffic.

Now, ensure that you can properly run Zeek on the pcap file from the
quickstart: TODO: Probably use Log::default_logdir=scratch and update
all following code blocks in the tutorial

   .. code:: console

      root@zeek-tutorial:/opt $ mkdir scratch
      root@zeek-tutorial:/opt $ cd scratch/
      root@zeek-tutorial:/opt/scratch $ zeek -r ../traces/quickstart.pcap
      root@zeek-tutorial:/opt/scratch $ ls conn.log
      files.log http.log packet_filter.log weird.log

If you get a few log files, then it properly read the quickstart pcap.
You’re now set up to do the tutorial!
