"""
Configuration for builds for Cirrus.
"""

load("ci/alpine/config.star", "config")
load("cirrus", environ = "env")

task_configs = {}
task_configs["alpine"] = config()

def main():
    print("CIRRUS_PR", environ.get("CIRRUS_PR"))
    print("CIRRUS_REPO_CLONE_TOKEN exists", "CIRRUS_REPO_CLONE_TOKEN" in environ)
    print("CIRRUS_REPO_FULL_NAME", environ.get("CIRRUS_REPO_FULL_NAME"))
    print("CIRRUS_CHANGE_IN_REPO", environ.get("CIRRUS_CHANGE_IN_REPO"))
    print("CIRRUS_WORKING_DIR", environ.get("CIRRUS_WORKING_DIR"))

    tasks = []
    for name in task_configs:
        t = task_configs[name]
        print(t)
        if environ.get("CIRRUS_REPO_FULL_NAME", "") == "timwoj/zeek":
            if t["zeek_task"]:
                tasks.append(t["zeek_task"]())
        elif environ.get("CIRRUS_REPO_FULL_NAME", "") == "timwoj/broker":
            if t["broker_task"]:
                tasks.append(t["broker_task"]())

    print(tasks)

    return tasks
