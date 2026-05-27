#!/usr/bin/env python3
"""
+-------------------+        +------------------------+
| main thread       |        | NullRouteClient thread |
+-------------------+        +------------------------+
|  main()           |        |                        |
|    Receiver.run() |        |                        |
|      recv_one()   |        |                        |
|        ws.recv()  | -----> |  queue.get()           |
|                   |        |    requests.post()     |
|                   |        |      zip() results
|                   |        |        m
|                   |        |         ws.send()      |
+-------------------+        +------------------------+
"""

import argparse
import dataclasses
import json
import logging
import os
import pathlib
import queue
import threading

import requests
import zeek_websocket
from websockets.sync.client import connect
from websockets.sync.connection import Connection

LOGGER = logging.getLogger("acld")

StopRequest = object()


@dataclasses.dataclass
class PubSubRule:
    ty: str
    arg: str
    comment: str
    rule_id: str
    rule: zeek_websocket.Value


@dataclasses.dataclass
class AddRules:
    pubsub_id: int
    reply_topic: str
    rules: list[PubSubRule]


@dataclasses.dataclass
class RemoveRules:
    pubsub_id: int
    reply_topic: str
    rules: list[PubSubRule]


@dataclasses.dataclass
class PostResult:
    results: list[dict]


class NullRouteClient:
    def __init__(
        self,
        *,
        job_queue: queue.Queue,
        ws: Connection,
        bulk_uri: str,
        namespace: str,
        api_key: str,
        job_queue_get_timeout: float,
        batch_jobs: int = 10,
        request_timeout=10.0,
    ):
        self.job_queue = job_queue
        self.ws = ws
        self.bulk_uri = bulk_uri
        self.namespace = namespace
        self.api_key = api_key
        self.queue_get_timeout = job_queue_get_timeout
        self.batch_jobs = batch_jobs
        self.stopped = False

        self.session = requests.Session()
        self.session.headers["X-API-Key"] = self.api_key
        self.session.headers["Content-Type"] = "application/json"

        self.request_timeout = request_timeout

        self.logger = logging.getLogger("acld.nullroute_client")

        self.pb = zeek_websocket.ProtocolBinding([])
        self.pb.outgoing()  # Discard

    def do_post(self, op: str, rules: list[PubSubRule]) -> PostResult:
        """ """
        assert op in ["add", "remove"]

        ipinfos = [{"ip": psr.arg, "comment": psr.comment} for psr in rules]

        req = {
            "operation": op,
            "namespace": self.namespace,
            "ipinfos": ipinfos,
        }

        LOGGER.debug("Sending %d ipinfos to %s", len(ipinfos), self.bulk_uri)

        response = self.session.post(
            self.bulk_uri, json=req, timeout=self.request_timeout
        )
        response.raise_for_status()
        data = response.json()

        return PostResult(data["results"])

    @staticmethod
    def result_to_event_name(op, result):
        """
        Map op and result to an event name to use as a reply.
        """
        lut = {
            "add": {
                "ok": "NetControl::pubsub_rule_added",
                "already_present": "NetControl::pubsub_rule_exists",
                "whitelisted": "NetControl::pubsub_rule_exists",
            },
            "remove": {
                "ok": "NetControl::pubsub_rule_removed",
                "not_found": "NetControl::pubsub_rule_removed",
            },
        }

        return lut[op].get(result, "NetControl::pubsub_rule_error")

    def publish_results(
        self,
        op: str,
        pubsub_id: int,
        reply_topic: str,
        rules: list[PubSubRule],
        result: PostResult,
    ) -> None:
        """
        Merge results with the original input IPs and publish back to Zeek via the WebSocket client.

        add:
        "ok", -> event pubsub_rule_added

        "already_present"
        "whitelisted" -> event pubsub_rule_exists

        remove:
        "ok",
        "not_found -> event pubsub_rule_removed

                   -> event pubsub_rule_error
        event_names = [
            "NetControl::pubsub_rule_added",
            "NetControl::pubsub_rule_removed",
            "NetControl::pubsub_rule_exists",
            "NetControl::pubsub_rule_error",
        ]

        """

        assert op in ["add", "remove"]
        assert len(rules) == len(result.results)

        for psr, psr_result in zip(rules, result.results):
            event_name = self.result_to_event_name(op, psr_result["status"])

            self.logger.debug("reply with %s for %s", event_name, psr.rule)

            args = [
                zeek_websocket.Value.Count(pubsub_id),
                psr.rule,
                "",  ## msg
            ]

            # This is kind of weird.
            event = zeek_websocket.Event(event_name, args, metadata=[])
            self.pb.publish_event(reply_topic, event)
            msg = self.pb.outgoing()
            assert msg

            self.ws.send(msg)

    def process_jobs(self, jobs: list[AddRules | RemoveRules]):
        """
        Given a list of mixed jobs (adding and removing), split them
        up into separate lists and do two requests to the acld server.

        The resulting events are published directly via the WebSocket
        client back to Zeek. Should be fast enough.
        """
        self.logger.info("Processing %d jobs", len(jobs))

        adds: list[PubSubRule] = []
        removes: list[PubSubRule] = []
        pubsub_id = None
        reply_topic = None

        # Jobs can be AddRules or RemoveRules where each contain
        # a PubSubRule instance, so split them here.
        for j in jobs:
            # Ensure pubsub_id and reply_topic within all
            # jobs is consistent.
            if pubsub_id is None and reply_topic is None:
                pubsub_id = j.pubsub_id
                reply_topic = j.reply_topic
            elif pubsub_id != j.pubsub_id:
                raise ValueError(f"inconsistent pubsub_id {pubsub_id} != {j.pubsub_id}")
            elif reply_topic != j.reply_topic:
                raise ValueError(f"inconsistent pubsub_id {pubsub_id} != {j.pubsub_id}")

            if isinstance(j, AddRules):
                adds.extend(j.rules)
            elif isinstance(j, RemoveRules):
                removes.extend(j.rules)
            else:
                raise ValueError(f"unhandled {j!r}")

        self.logger.info("%d IPs to add, %d IPs to remove", len(adds), len(removes))

        # Do the adds first.
        assert pubsub_id is not None
        assert reply_topic is not None

        result = self.do_post("add", adds)
        if len(result.results) != len(adds):
            raise ValueError(
                f"wrong number of results {len(result.results)} vs {len(adds)}"
            )
        self.publish_results("add", pubsub_id, reply_topic, adds, result)

        result = self.do_post("remove", removes)
        if len(result.results) != len(removes):
            raise ValueError(
                f"wrong number of results {len(result.results)} vs {len(adds)}"
            )
        self.publish_results("remove", pubsub_id, reply_topic, removes, result)

    def run(self):
        """
        Runner of the NullRouteClient.
        """
        self.logger.info("Running!")
        jobs = []
        while not self.stopped:
            timed_out = False
            try:
                job = self.job_queue.get(timeout=self.queue_get_timeout)
                if job is StopRequest:
                    self.stopped = True
                    break

            except queue.Empty:
                self.logger.debug("Timeout!")
                timed_out = True
            else:
                jobs += [job]

            if (jobs and timed_out) or len(jobs) >= self.batch_jobs:
                try:
                    self.process_jobs(jobs)
                except:
                    LOGGER.exception("Bad")
                    self.stop()
                    break

                jobs = []

        self.logger.info("Stopped")

    def stop(self):
        """
        Stop this NullRoute client.
        """
        self.logger.info("Stopping")
        self.stopped = True
        self.job_queue.put_nowait(StopRequest)


class Receiver:
    """
    Receive events from Zeek, place them into job_queue where the
    NullRouteClient will pick them out and reply to Zeek.

    acld-ng <-- HTTP --> broker-acld.py <-- websocket --> Zeek
    """

    def __init__(
        self,
        *,
        ws: Connection,
        request_topic: str,
        job_queue: queue.Queue,
    ):
        self.ws = ws
        self.request_topic = request_topic
        self.pb = zeek_websocket.ProtocolBinding([self.request_topic])

        self.job_queue = job_queue

    def recv_one(self):
        # This client is driven via events from Zeek.
        msg = self.ws.recv(decode=False)
        self.pb.handle_incoming(msg)  # Rust rust rust

        topic_event = self.pb.receive_event()
        # print("TE", topic_event)
        if topic_event is not None:
            topic, event = topic_event
            name, args = event.name, event.args
            _ = name
            reply_topic, pubsub_id, rules = args
            # LOGGER.debug("event_name=%s reply_topic=%s rules=%s", name, reply_topic, rules)
            # print("RULES", rules)

            if name == "NetControl::pubsub_add_rules":
                job = AddRules(
                    pubsub_id=pubsub_id.value, reply_topic=reply_topic.value, rules=[]
                )
            elif name == "NetControl::pubsub_remove_rules":
                job = RemoveRules(
                    pubsub_id=pubsub_id.value, reply_topic=reply_topic.value, rules=[]
                )
            else:
                raise ValueError(f"unexpected event {name}")

            # Copy all PubSubRule instances from the received vector.
            for i, r in enumerate(rules.value):
                psr = r.as_record(PubSubRule)  # rust rust rust
                job.rules += [psr]

            # Just put the job into the queue, the NullRouteClient
            # will pick it up.
            self.job_queue.put(job)

    def run(self):
        subscriptions = self.pb.outgoing()
        assert subscriptions
        self.ws.send(subscriptions)
        ack = self.ws.recv()
        ack = json.loads(ack)
        if ack.get("type") != "ack" or "endpoint" not in ack:
            LOGGER.error("Bad ack received from Zeek: %r", ack)
            raise ValueError(repr(ack))

        LOGGER.info("Got ack %s", ack)

        while True:
            try:
                self.recv_one()
            except KeyboardInterrupt:
                break


def setup_nullroute_client(
    args, job_queue: queue.Queue, ws: Connection
) -> NullRouteClient:
    """
    This thing isn't all that special? It just does a POST to /nullroute-bulk
    with a bunch of IPs to block and gets back an array of statuses that match
    the order of what was passed in?

    This is is an excerpt from the original broker-acld.py code:

        res = client.post(....)
        res = res.json()
        for add, r in zip(adds, res["result"])
            add["result"] = r["result"]


    The results should be pushed as events via the WebSocket client
    back to Zeek using the NetControl::pubsub_rule_added event that
    receives id, rule and msg.
    """
    api_key: str = ""
    if args.nullroute_api_key:
        api_key = args.nullroute_api_key
    elif "ACLDNG_API_TOKEN" in os.environ:
        api_key = os.environ["ACLDNG_API_TOKEN"]
    else:
        try:
            api_key = (
                pathlib.Path("/usr/local/etc/acld-ng-apitoken").read_text().strip()
            )
        except FileNotFoundError as e:
            LOGGER.warning("%s", e)

    return NullRouteClient(
        job_queue=job_queue,
        ws=ws,
        bulk_uri=args.nullroute_bulk_uri,
        namespace=args.nullroute_namespace,
        api_key=api_key,
        batch_jobs=args.nullroute_batch_jobs,
        job_queue_get_timeout=args.nullroute_job_queue_get_timeout,
    )


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--log-level", default="INFO")
    parser.add_argument(
        "--ws-uri",
        default="ws://127.0.0.1:27759/v1/messages/json",
        help="The URI for Zeek's WebSocket API on the manager",
    )
    parser.add_argument("--ws-open-timeout", type=int, default=10)
    parser.add_argument(
        "--request-topic",
        type=str,
        default="lbl/acld/request",
        help="The topic to subscribe to and listen of NetControl::pubsub_* events",
    )

    parser.add_argument(
        "--nullroute-bulk-uri", default="http://localhost:8080/nullroute-bulk"
    )
    parser.add_argument("--nullroute-api-key", default="")
    parser.add_argument("--nullroute-namespace", default="development")
    parser.add_argument("--nullroute-job-queue-get-timeout", type=float, default=0.01)
    parser.add_argument("--nullroute-batch-jobs", type=int, default=10)

    args = parser.parse_args()

    logging.basicConfig(level=getattr(logging, args.log_level.upper()))

    job_queue = queue.Queue()
    nullroute_client: NullRouteClient | None = None
    nullroute_thread: threading.Thread | None = None

    try:
        with connect(args.ws_uri, open_timeout=args.ws_open_timeout) as ws:
            LOGGER.info("Connected...")
            nullroute_client = setup_nullroute_client(args, job_queue, ws)
            nullroute_thread = threading.Thread(target=nullroute_client.run)
            nullroute_thread.start()

            receiver = Receiver(
                ws=ws, request_topic=args.request_topic, job_queue=job_queue
            )
            receiver.run()
    finally:
        try:
            if nullroute_client is not None:
                nullroute_client.stop()
                assert nullroute_thread is not None
                nullroute_thread.join()
        except Exception as e:
            LOGGER.exception("Exception shutting down nullroute_client: %s", e)


if __name__ == "__main__":
    main()
