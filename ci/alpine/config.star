load("github.com/cirrus-modules/helpers", "task", "container", "script")
load("cirrus", "fs")

task_name = "alpine"

def zeek_task():
    return task(name=task_name,
                instance=container(
                    dockerfile="ci/alpine/Dockerfile",
                    cpu=4,
                    memory=16384),
                instructions=[
                    script("part1", "echo 'Building Alpine part 1'"),
                    script("part2", "echo 'Building Alpine part 2'"),
                ])

def config():
    return {"task_name": task_name,
            "zeek_task": zeek_task,
            "broker_task": None}
