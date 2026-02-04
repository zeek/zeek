
.. _script-usage-errors:

==============================
Finding Potential Usage Errors
==============================

Usage errors concern variables used-but-not-guaranteed-set or
set-but-not-ever-used.  Zeek generates reports for these if you specify
the ``-u`` flag.  It exits after producing the report, so if it simply exits
with no output, then it did not find any usage errors.

Variables reported as "used without definition" appear to have a code path
to them the could access their value even though it has not been initialized.
If upon inspection you determine that there is no actual hazard, you can
mark the definition with an :zeek:attr:`&is_assigned` attribute to assure the optimizer
that the value will be set.

Variables reported as "assignment unused" have a value assigned to them
that is meaningless since prior to any use of that value, another value
is assigned to the same variable.  Such assignments are worth inspecting
as they sometimes reflect logic errors.  Similar logic applies to unused
event handlers, hooks, and functions.  You can suppress these reports by
adding an :zeek:attr:`&is_used` attribute to the original definition.  If the
determination is indeed incorrect, that represents a bug in Zeek's analysis,
so something to report via the Issue Tracker.
