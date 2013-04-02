..	-*- mode: rst-mode -*-
..
.. Version number is filled in automatically.
.. |version| replace:: 1.54

===============================================
Ruby Bindings for Broccoli
===============================================

.. rst-class:: opening

    This is the broccoli-ruby extension for Ruby which provides access
    to the Broccoli API.  Broccoli is a library for
    communicating with the Bro Intrusion Detection System.


Download
========

You can find the latest Broccoli-Ruby release for download at
http://www.bro.org/download.

Broccoli-Ruby's git repository is located at `git://git.bro.org/broccoli-ruby.git
<git://git.bro.org/broccoli-ruby.git>`__. You can browse the repository
`here <http://git.bro.org/broccoli-ruby.git>`__.

This document describes Broccoli-Ruby |version|. See the ``CHANGES``
file for version history.


Installation
============

To install the extension:

1. Make sure that the ``broccoli-config`` binary is in your path.
   (``export PATH=/usr/local/bro/bin:$PATH``)

2. Run ``sudo ruby setup.rb``.

To install the extension as a gem (suggested):

1. Install `rubygems <http://rubygems.org>`_.

2. Make sure that the ``broccoli-config`` binary is in your path.
   (``export PATH=/usr/local/bro/bin:$PATH``)

3. Run, ``sudo gem install rbroccoli``.

Usage
=====

There aren't really any useful docs yet.  Your best bet currently is
to read through the examples.

One thing I should mention however is that I haven't done any optimization
yet.  You may find that if you write code that is going to be sending or
receiving extremely large numbers of events, that it won't run fast enough and
will begin to fall behind the Bro server.  The dns_requests.rb example is
a good performance test if your Bro server is sitting on a network with many
dns lookups.

Contact
=======

If you have a question/comment/patch, see the Bro `contact page
<http://www.bro.org/contact/index.html>`_.
