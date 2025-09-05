#!/usr/bin/env python3

import os
import smtplib
import ssl
from email.mime.text import MIMEText

from gql import Client, gql
from gql.transport import exceptions
from gql.transport.aiohttp import AIOHTTPTransport

# This is hardcoded because it doesn't make sense to set as a Cirrus secret
# and it doesn't come as part of the Cirrus build environment.
CIRRUS_GRAPHQL_ENDPOINT = "https://api.cirrus-ci.com/graphql"

# These are all defined as secrets in the Cirrus Zeek project, and imported
# via the Cirrus environment.
SMTP_HOST = os.getenv("ZEEK_SMTP_HOST")
SMTP_PORT = os.getenv("ZEEK_SMTP_PORT")
SMTP_USER = os.getenv("ZEEK_SMTP_USERNAME")
SMTP_PASS = os.getenv("ZEEK_SMTP_PASSWORD")
CIRRUS_GRAPHQL_TOKEN = os.getenv("ZEEK_CIRRUS_GRAPHQL_TOKEN")

# These are defined as part of the Cirrus build environment.
CIRRUS_CRON = os.getenv("CIRRUS_CRON")
CIRRUS_BUILD_ID = os.getenv("CIRRUS_BUILD_ID")

graphql_headers = {"Authorization": f"Bearer {CIRRUS_GRAPHQL_TOKEN}"}
gql_transport = AIOHTTPTransport(url=CIRRUS_GRAPHQL_ENDPOINT, headers=graphql_headers)
gql_client = Client(transport=gql_transport)

query = gql("""
    query GetFailedBuild {
      ownerInfoByName(platform: "github", name: "zeek") {
        builds(last: 20, status: FAILED) {
          edges {
            node {
              id
              repository {
                name
              }
              tasks {
                id
                name
                status
              }
            }
          }
        }
      }
    }
""")

msg_text = f"The Cirrus build started by the {CIRRUS_CRON} cron job failed.\n\n"

try:
    result = gql_client.execute(query)
except exceptions.TransportQueryError as tqe:
    msg_text += f"Query error while requesting GraphQL data: {tqe}"
except exceptions.TransportProtocolError as tpe:
    msg_text += f"Protocol error while requesting GraphQL data: {tpe}"
except exceptions.TransportServerError as tse:
    msg_text += f"Server error while requesting GraphQL data: {tse}"
else:
    failed_tasks = []

    # Find the build we care about. We get all of the builds for the zeek org
    # here so we have to filter both by repository and by build ID. Once we
    # have it, find the failed tasks from it.
    found_build = False
    builds = result.get("ownerInfoByName", {}).get("builds", {}).get("edges", {})
    for b in builds:
        node = b.get("node", {})
        if not node:
            continue

        repo_name = node.get("repository", {}).get("name", "")
        if repo_name != "zeek":
            continue

        if node.get("id", "") != f"{CIRRUS_BUILD_ID}":
            continue

        found_build = True

        tasks = node.get("tasks", {})
        for t in tasks:
            if t.get("status", "") != "FAILED":
                continue

            failed_tasks.append(t)

    if not found_build:
        msg_text += f"Failed to find build {CIRRUS_BUILD_ID} in the GraphQL output!"
    else:
        msg_text += "The following tasks failed: \n\n"
        for t in failed_tasks:
            msg_text += (
                f"\t{t.get('name', '')}: https://cirrus-ci.com/task/{t.get('id', '')}\n"
            )

msg = MIMEText(msg_text)
msg["Subject"] = f"Cirrus {CIRRUS_CRON} task failed"
msg["From"] = "noreply@zeek.org"
msg["To"] = "zeek-commits-internal@zeek.org"

# This should get logged into the Cirrus output.
print(msg_text)

try:
    context = ssl.SSLContext(protocol=ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE

    smtp = smtplib.SMTP(SMTP_HOST, SMTP_PORT)
    smtp.ehlo()
    smtp.starttls(context=context)
    smtp.ehlo()
    smtp.login(SMTP_USER, SMTP_PASS)
    smtp.send_message(msg)
    smtp.quit()
except Exception as e:
    print(f"Failed to send email: {e}")
