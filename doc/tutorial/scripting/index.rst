################
 Zeek Scripting
################

We have previously encountered bits of Zeek's scripting language, but
have not examined it in any in depth. Let's close that gap, in three steps!

First, a simple walkthrough of language features and how to do various
common tasks. Where needed, we'll link to the :doc:`script
reference </reference/zeekscript/index>` to further explain the concepts.

Second, we will build up a small Zeek script from scratch. This should
cover many of the necessary parts for common detections. It's meant
to supplement other resources, including `try.zeek.org
<https://try.zeek.org>`_ and the :doc:`script reference
</reference/zeekscript/index>`. The scripting reference covers each language
construct, while this step in the tutorial aims to explain essential
components of the scripting language, required to build a custom script.

Third, a basic walkthrough of Zeek's Javascript support as an alternative
to scripting in Zeekscript.

Ideally, this tutorial wouldn't assume any level of programming experience.
However, we won't go into the fundamentals of several constructs, instead
following a "learning by doing" approach. If you do not have much programming
experience, you may need to consult a programming basics tutorial first.

.. toctree::
   :maxdepth: 1

   basics
   tutorial-example
   javascript
