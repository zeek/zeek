load("./zeek.star", "zeek_task")

task_name = "alpine"

def config():
    return {"task_name": task_name,
            "zeek_task": zeek_task,
            "broker_task": None}
