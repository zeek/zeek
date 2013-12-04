.. _script-packages:

Bro Package Index
=================

Bro has the following script packages (e.g. collections of related scripts in
a common directory).  If the package directory contains a ``__load__.bro``
script, it supports being loaded in mass as a whole directory for convenience.

Packages/scripts in the ``base/`` directory are all loaded by default, while
ones in ``policy/`` provide functionality and customization options that are
more appropriate for users to decide whether they'd like to load it or not.

.. broxygen:package_index:: *
