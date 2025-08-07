load("github.com/cirrus-modules/helpers", "task", "container", "script")

task_name = "alpine"

def zeek_task():
    container_file = fs.read("Dockerfile")
    return task(name=task_name,
                instance=container(container_file),
                instructions=[
                    script("Building alpine"),
                ])

def config():
    return {"task_name": task_name,
            "zeek_task": zeek_task,
            "broker_task": None}
