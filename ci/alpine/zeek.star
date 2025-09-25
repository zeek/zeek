load("../starlark/common.star", "resources", "make_docker_task")
load("../starlark/common-zeek.star",
     "configure_opt_default_release",
     "only_if_pr_master_or_release",
     "skip_if_pr_not_full_ci",
     "default_environment",
     "ci_template",
     "default_instructions")

def zeek_task():
    return make_docker_task("alpine",
                            "ci/alpine/Dockerfile",
                            resources()["linux"],
                            default_environment(configure_opt_default_release()),
                            default_instructions(),
                            skip_if_pr_not_full_ci(),
                            only_if_pr_master_or_release(),
                            ci_template())
