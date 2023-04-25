# @TEST-DOC: Test that chains of suspend_processing/continue_processing report the correct suspension status
# @TEST-EXEC: zeek %INPUT >output
# @TEST-EXEC: btest-diff output

event zeek_init()
{
# Paired suspend/continue should unsuspend.
suspend_processing();
continue_processing();
print is_processing_suspended(); # F

# Another continue after unsuspending shouldn't cause it to be suspended.
continue_processing();
print is_processing_suspended(); # F

# Test suspend "stack" by suspending twice
suspend_processing();
suspend_processing();

# First continue should still be suspended
continue_processing();
print is_processing_suspended(); # T

# Second continue should break the suspension
continue_processing();
print is_processing_suspended(); # F

# Third continue should still be marked as not suspended.
continue_processing();
print is_processing_suspended(); # F
}
