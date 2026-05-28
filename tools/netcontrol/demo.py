#!/usr/bin/env python3
"""
ws-acld.py - Python side talking to acldng via the netcontrol/pubsub plugin.
"""

import argparse
import dataclasses
import logging
import os
import pathlib
import queue
import threading

import requests
from zeekws.zeekws import Client, RawArg, count, enum

LOGGER = logging.getLogger("acld")

StopRequest = object()


@dataclasses.dataclass
class PubSubRule:
    ty: enum
    arg: str
    comment: str
    rule_id: str
    rule: RawArg  # unparsed


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
        zeek: Client,
        bulk_uri: str,
        namespace: str,
        api_key: str,
        job_queue_get_timeout: float,
        batch_jobs: int = 10,
        request_timeout=10.0,
    ):
        self.job_queue = job_queue
        self.zeek = zeek
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
        """

        assert op in ["add", "remove"]
        assert len(rules) == len(result.results)

        for psr, psr_result in zip(rules, result.results):
            event_name = self.result_to_event_name(op, psr_result["status"])

            self.logger.debug("reply with %s for %s", event_name, psr.rule)
            self.zeek.publish(reply_topic, event_name, [count(pubsub_id), psr.rule, ""])

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
        Run method of the NullRouteClient

        Consume jobs from the queue until stopped.
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
                except Exception as e:
                    LOGGER.exception("Bad")
                    self.stop()
                    self.zeek.stop(exc_val=e)
                    break

                jobs = []

        self.logger.info("Stopped")

    def stop(self):
        """
        Make the NullRoute client's run method stop.
        """
        self.logger.info("Stopping")
        self.stopped = True
        self.job_queue.put_nowait(StopRequest)

    @staticmethod
    def create(job_queue: queue.Queue, zeek: Client, args: argparse.Namespace):
        """
        Create a new NullRouteClient.

        Tries to find an api_key either in the command-line, environment
        or a well-known filename /usr/local/etc/acld-ng-apitoken.

        Args:
            job_queue: The queue from which to pull jobs.
            zeek: Used for publishing back to Zeek
            args: The command-line arguments
        """
        api_key: str = ""
        if args.nullroute_api_key:
            api_key = args.nullroute_api_key
        elif "ACLDNG_API_TOKEN" in os.environ:
            api_key = os.environ["ACLDNG_API_TOKEN"]
        else:
            api_key = pathlib.Path(args.nullroute_api_key_filename).read_text().strip()

        return NullRouteClient(
            job_queue=job_queue,
            zeek=zeek,
            bulk_uri=args.nullroute_bulk_uri,
            namespace=args.nullroute_namespace,
            api_key=api_key,
            batch_jobs=args.nullroute_batch_jobs,
            job_queue_get_timeout=args.nullroute_job_queue_get_timeout,
        )


def main():
    """
    Entry point.

    Connects to Zeek using zeekws.Client, spawns the NullRouteClient
    thread, starts consuming events until stopped, places "jobs" into
    the job_queue for the NullRouteClient to pick up. NullRouteClient
    uses zeekws.Client.publish() to send the result of the jobs back
    to Zeek.
    """
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
    parser.add_argument(
        "--nullroute-api-key-filename", default="/usr/local/etc/acld-ng-apitoken"
    )
    parser.add_argument("--nullroute-namespace", default="development")
    parser.add_argument("--nullroute-job-queue-get-timeout", type=float, default=0.01)
    parser.add_argument("--nullroute-batch-jobs", type=int, default=10)

    args = parser.parse_args()

    logging.basicConfig(level=getattr(logging, args.log_level.upper()))

    job_queue = queue.Queue()
    nullroute_client: NullRouteClient | None = None
    nullroute_thread: threading.Thread | None = None

    with Client(args.ws_uri, topics=[args.request_topic]) as zeek:
        """
        Zeek event handlers enqueue jobs to NullRouteClient.
        """

        @zeek.on("NetControl::pubsub_add_rules")
        def add_rules(reply_topic: str, pubsub_id: count, rules: list[PubSubRule]):
            job = AddRules(pubsub_id=pubsub_id, reply_topic=reply_topic, rules=rules)
            job_queue.put(job)

        @zeek.on("NetControl::pubsub_remove_rules")
        def remove_rules(reply_topic: str, pubsub_id: count, rules: list[PubSubRule]):
            job = RemoveRules(pubsub_id=pubsub_id, reply_topic=reply_topic, rules=rules)
            job_queue.put(job)

        LOGGER.info("Starting NullrouteClientT thread ...")
        nullroute_client = NullRouteClient.create(job_queue, zeek, args)
        nullroute_thread = threading.Thread(target=nullroute_client.run)
        nullroute_thread.start()

        try:
            zeek.consume()
        except KeyboardInterrupt:
            LOGGER.info("Interrupted")
        finally:
            # Shutdown
            try:
                nullroute_client.stop()
                nullroute_thread.join()
            except Exception as e:
                LOGGER.exception("Exception shutting down nullroute_client: %s", e)

    LOGGER.info("Done")


if __name__ == "__main__":
    main()
