"""
A collection of functions for all builds
"""

load("github.com/cirrus-modules/helpers", "container", "task")

def resources():
    return {
        "linux": {
            "cpu": 4,
            "memory": 16384,
            "greedy": True,
        },
        "freebsd": {
            "cpu": 8,
            "memory": 16384,
            "greedy": True,
        },
        "macos": {
            "cpu": 4,
            "memory": 16384,
            "greedy": True,
        },
        "windows": {
            "cpu": 8,
            "memory": 8192,
        },
    }

def make_task(task_name, inst, environment, instructions, skip_options = "", only_if_options = "", ci_template = {}):
    """
    The default task() definition from Cirrus' helpers doesn't cover all of the options you can put
    into one. This expands that definition a little.

    Args:
      task_name: The name of the task. This will be displayed on the task list for the build.
      inst: An instance definition for the task. This can be a container or another type of instance.
      environment: The contents of the task's env entry.
      skip_options: The contents of the task's skip_ci entry. Can be left blank to omit it.
      only_if_options: The contents of the task's only_if entry. Can be left blank to omit it.
      ci_template: A dictionary of other entries that should be added to the task definition.

    Returns:
      A task with all of the specified options.
    """
    t = task(name = task_name, instance = inst, env = environment, instructions = instructions)

    if skip_options:
        t.update({"skip": skip_options})

    if only_if_options:
        t.update({"only_if": only_if_options})

    if ci_template:
        t.update(ci_template)

    return t

def make_docker_task(task_name, dockerfile_path, resources, environment, instructions, skip_options = "", only_if_options = "", ci_template = {}):
    """
    A specialization of the make_task() helper that builds a container to pass in as an argument.

    Args:
      task_name: The name of the task. This will be displayed on the task list for the build.
      dockerfile_path: The path to the Dockerfile for for this container. This should be a path
        relative to the top-level of the repository.
      resources: A dictionary of resource options to request for the container instance. This
        should the following fields:
        'cpu': The number of CPUs to request for instances.
        'memory': The amount of memory in bytes to request for instances.
        'greedy': A boolean value for whether Cirrus' greedy mode should be enabled for the container.
      container: The result from the container() Cirrus helper.
      environment: The contents of the task's env entry.
      skip_options: The contents of the task's skip_ci entry. Can be left blank to omit it.
      only_if_options: The contents of the task's only_if entry. Can be left blank to omit it.
      ci_template: A dictionary of other entries that should be added to the task definition.

    Returns:
      A task with all of the specified options.
    """
    cont = container(
        dockerfile = dockerfile_path,
        cpu = resources["cpu"],
        memory = resources["memory"],
        greedy = resources["greedy"],
    )

    return make_task(task_name, cont, environment, instructions, skip_options, only_if_options, ci_template)
