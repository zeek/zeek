#!/usr/bin/env python3

import glob
import hashlib
import json
import os
import re
import urllib.request

PR_NUMBER = os.getenv("CIRCLE_PULL_REQUEST", "")
GH_API_TOKEN = os.getenv("GH_TOKEN", "")
GIT_TAG = os.getenv("CIRCLE_TAG", "")
GIT_BRANCH = os.getenv("CIRCLE_BRANCH", "")

params = {}
if PR_NUMBER:
    url = PR_NUMBER
    url = url.replace("https://github.com", "https://api.github.com/repos")
    url = url.replace("/pull/", "/pulls/")

    print(f"Requesting {url} to get PR labels from GitHub")

    headers = {
        "content-type": "Accept: application/vnd.github+json",
    }

    if GH_API_TOKEN:
        headers["Authorization"] = f"Bearer {GH_API_TOKEN}"

    req = urllib.request.Request(url, headers=headers)
    response = urllib.request.urlopen(req)
    resp_json = json.loads(response.read().decode("utf8"))

    for label in resp_json.get("labels", []):
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

    # This field will be set to MEMBER if the user that opened a PR is a member of the
    # Zeek github organization. This lets us track internal builds.
    if resp_json.get("author_association", "NONE") == "MEMBER":
        params["is_internal_build"] = True

elif GIT_BRANCH == "master" or re.match(r"^release/.*$", GIT_BRANCH):
    # Builds from master should always be considered internal builds.
    params["is_internal_build"] = True

if GIT_TAG and re.match(r"^v\d+\.\d+\.\d+(-rc[0-9]+)?$", GIT_TAG):
    params["has_release_tag"] = True

# Build up a set of hashes on the Dockerfiles for the build images to be used as version
# numbers in the dockerhub repo. Remove windows because it's not used, but we keep the
# Dockerfile for historical reasons.
platforms = sorted([p.split("/")[1] for p in glob.glob("ci/*/Dockerfile")])
if "windows" in platforms:
    platforms.remove("windows")

# Build a version string for each platform. For release branches, we prepend the version number so
# the cleanup task doesn't nuke versions from the release branches.
image_version = ""
m = re.match(r"^release/(\d+\.\d+)$", GIT_BRANCH)
if m:
    image_version = m.group(1)
else:
    image_version = "master"

for p in platforms:
    with open(f"ci/{p}/Dockerfile", "rb") as df:
        # I tried to use hashlib.file_digest here, but apparently the standard python on Circle's
        # runners is old enough that it doesn't support that.
        df_str = df.read()
        params[f"{p.replace('-', '_').replace('.', '_')}_image_version"] = (
            f"{image_version}-{hashlib.sha256(df_str).hexdigest()[:7]}"
        )

with open("/tmp/parameters.json", "w") as params_file:
    json.dump(params, params_file)
