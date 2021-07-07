# The entry point for the cluster agent. It only runs bootstrap logic for
# launching via the Supervisor. If we're not running the Supervisor, this does
# nothing.

@load ./boot
