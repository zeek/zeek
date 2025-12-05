####################
 Scripting Tutorial
####################

We have previously seen Zeek’s scripting language, but have not examined
the scripting language in depth. This scripting tutorial will consist of
three parts.

First, a simple walkthrough of language features and how to do various
common tasks. Where needed, there will be links to the :doc:`script
reference </script-reference/index>` to further explain the concepts.

Second, we will build up a small Zeek script from scratch. This should
get many of the necessary parts for any given detection. This is meant
to supplement other references---namely, `try.zeek.org
<https://try.zeek.org>`_ and the :doc:`script reference
</script-reference/index>`. try.zeek.org provides a more interactive
tutorial. The scripting reference goes through each language construct.
This is meant to simply understand the essential components of the
scripting language, then make a custom script.

Third, a basic walkthrough of Javascript as an alternative.

.. note::

   There will also, eventually, be a section about incorporating this
   script in a cluster setup.

This tutorial will assume some knowledge of programming languages like
Python before getting started. Specifics of Zeek script will be
discussed, but any general programming concepts will not.

.. toctree::
   :maxdepth: 1

   basics
   tutorial-example
   javascript
