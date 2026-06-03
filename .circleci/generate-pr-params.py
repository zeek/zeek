#!/usr/bin/env python3

import json
import os
import urllib.request

PR_NUMBER = os.getenv("CIRCLE_PULL_REQUEST", "")
GH_API_TOKEN = os.getenv("GH_TOKEN", "")

params = {}
if len(PR_NUMBER) > 0:
    url = PR_NUMBER
    url = url.replace("https://github.com", "https://api.github.com/repos")
    url = url.replace("/pull/", "/issues/")
    url += "/labels"

    print(f"Requesting {url} to get PR labels from GitHub")

    headers = {
        "content-type": "Accept: application/vnd.github+json",
    }

    if GH_API_TOKEN:
        headers["Authorization"] = f"Bearer: {GH_API_TOKEN}"

    req = urllib.request.Request(url, headers=headers)
    response = urllib.request.urlopen(req)
    resp_json = json.loads(response.read().decode("utf8"))

    for label in resp_json:
        name = label.get("name", "")
        print(f"Found GitHub label {name} on PR, enabling flag")
        if name == "CI: Benchmark":
            params["pr_label_benchmark"] = True
        elif name == "CI: Cluster Testing":
            params["pr_label_cluster_test"] = True
        elif name == "CI: Full":
            params["pr_label_full"] = True
        elif name == "CI: Skip All":
            params["pr_label_skip_all"] = True
        elif name == "CI: Spicy":
            params["pr_label_spicy"] = True
        elif name == "CI: Windows":
            params["pr_label_windows"] = True
        elif name == "CI: ZAM":
            params["pr_label_zam"] = True
        elif name == "CI: Zeekctl":
            params["pr_label_zeekctl"] = True

    if not params:
        print("No GitHub labels found on PR")

with open("/tmp/parameters.json", "w") as params_file:
    json.dump(params, params_file)
