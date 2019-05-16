:orphan:

Package: policy/integration/barnyard2
=====================================

Integration with Barnyard2.

:doc:`/scripts/policy/integration/barnyard2/__load__.zeek`


:doc:`/scripts/policy/integration/barnyard2/types.zeek`

   This file is separate from the base script so that dependencies can
   be loaded in the correct order.

:doc:`/scripts/policy/integration/barnyard2/main.zeek`

   This script lets Barnyard2 integrate with Zeek.  It receives alerts from
   Barnyard2 and logs them.  In the future it will do more correlation
   and derive new notices from the alerts.

