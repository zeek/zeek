load("cirrus", environ="env")
load("github.com/cirrus-modules/helpers", "task", "container", "script")

task_list = {}
load("./ci/alpine/cirrus.star", "config")
task_list["alpine"] = config

def main():
    print("CIRRUS_PR", environ.get("CIRRUS_PR"))
    print("CIRRUS_REPO_CLONE_TOKEN exists", "CIRRUS_REPO_CLONE_TOKEN" in environ)
    print("CIRRUS_REPO_FULL_NAME", environ.get("CIRRUS_REPO_FULL_NAME"))
    print("CIRRUS_CHANGE_IN_REPO", environ.get("CIRRUS_CHANGE_IN_REPO"))
    print("CIRRUS_WORKING_DIR", environ.get("CIRRUS_WORKING_DIR"))

    tasks = []
    for t in task_list:

        if environ.get("CIRRUS_REPO_FULL_NAME", "") == "zeek/zeek":
            if t['zeek_task']:
                tasks.append(t['zeek_task'])
        elif environ.get("CIRRUS_REPO_FULL_NAME", "") == "zeek/broker":
            if t['broker_task']:
                tasks.append(t['broker_task'])

    return tasks
