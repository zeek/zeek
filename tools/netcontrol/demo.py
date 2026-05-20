import argparse
import asyncio
import dataclasses
import json
import logging
import os
import pathlib
import queue
import threading

import websockets
import zeek_websocket

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
    rules: list[PubSubRule]


@dataclasses.dataclass
class RemoveRules:
    pubsub_id: int
    rules: list[PubSubRule]


@dataclasses.dataclass
class PostResult:
    results: list[dict]


class NullRouteClient:
    def __init__(
        self,
        *,
        request_queue: queue.Queue,
        ws: websockets.ClientConnection,
        api_key: str,
        queue_get_timeout: float,
        max_jobs: int = 10,
    ):
        self.request_queue = request_queue
        self.ws = ws
        self.api_key = api_key
        self.queue_get_timeout = queue_get_timeout
        self.max_jobs = max_jobs
        self.stopped = False

        self.logger = logging.getLogger("acld.nullroute_client")

    def do_post(self, op: str, rules: list[PubSubRule]) -> PostResult:
        """ """
        assert op in ["add", "remove"]

        # XXX: TODO: Do an actual POST request.
        fake_results = [
            {"status": ""},
        ]
        return PostResult(fake_results)

    def publish_results(self, op: str, rules: list[PubSubRule], results: PostResult):
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

        # Jobs can be AddRules or RemoveRules where each contain
        # a PubSubRule instance, so split them here.
        for j in jobs:
            if isinstance(j, AddRules):
                adds.extend(j.rules)
            elif isinstance(j, RemoveRules):
                removes.extend(j.rules)
            else:
                raise ValueError(f"unhandled {j!r}")

        print("adds: ", ",".join(a.arg for a in adds))

        result = self.do_post("add", adds)
        self.publish_results("add", adds, result)

        # Do the http POST with the array of addresses, stitch
        # together the result for the response and send it out.

    def run(self):
        """
        Runner of the NullRouteClient.
        """
        self.logger.info("Running!")
        jobs = []
        while not self.stopped:
            timed_out = False
            try:
                job = self.request_queue.get(timeout=self.queue_get_timeout)
                if job is StopRequest:
                    self.stopped = True
                    break

            except queue.Empty:
                self.logger.debug("Timeout!")
                timed_out = True
                if jobs:
                    # submit tasks
                    self.process_jobs(jobs)
            else:
                jobs += [job]

            # How many jobs to dequeue before processing them.
            if jobs and timed_out or len(jobs) >= self.max_jobs:
                self.process_jobs(jobs)
                jobs = []

        self.logger.info("Stopped")

    def stop(self):
        """
        Stop this NullRoute client.
        """
        self.logger.info("Stopping")
        self.stopped = True
        self.request_queue.put_nowait(StopRequest)


class Proxy:
    """
    Proxy sits between Zeek and ACLd.

    Receive events from Zeek

    acld-ng <-- HTTP --> broker-acld.py <-- websocket --> Zeek
    """

    def __init__(
        self,
        *,
        websocket_client: websockets.ClientConnection,
        request_topic: str,
        request_queue: queue.Queue,
    ):
        self.websocket_client: websockets.ClientConnection = websocket_client
        self.request_topic = request_topic
        self.pb = zeek_websocket.ProtocolBinding([self.request_topic])

        self.request_queue = request_queue

    async def run(self):
        subscriptions = self.pb.outgoing()
        assert subscriptions
        await self.websocket_client.send(subscriptions)
        ack = await self.websocket_client.recv()
        ack = json.loads(ack)
        if ack.get("type") != "ack" or "endpoint" not in ack:
            LOGGER.error("Bad ack received from Zeek: %r", ack)
            raise ValueError(repr(ack))

        LOGGER.info("Got ack %s", ack)

        while True:
            # This client is driven via events from Zeek.
            msg = await self.websocket_client.recv(decode=False)
            # print("GOT MESSAGE!", msg)

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

                job = AddRules(pubsub_id=pubsub_id.value, rules=[])

                for i, r in enumerate(rules.value):
                    psr = r.as_record(PubSubRule)  # rust rust rust
                    job.rules += [psr]

                self.request_queue.put(job)

                # print("XXX XXX QUEUE SIZE", self.request_queue.qsize())
                # print("pssr", pssr)

                # reply_event = zeek_websocket.Event(
                #    name=event_names[ADDED],
                #    args=[pubsub_id, rule, "done!"],
                #    metadata=[],
                # )

                # self.pb.publish_event(reply_topic.value, reply_event)

                # This can deadlock when we write too much
                # because then the transport is "paused"
                # because probably only continue once we have
                # consumed more bytes.
                # while out := self.pb.outgoing():
                #    await self.websocket_client.send(out, text=True)


def setup_nullroute_client(
    args, request_queue: queue.Queue, ws: websockets.ClientConnection
) -> NullRouteClient:
    """
    TODO: Needs an API token, URL and stuff.

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
    if "ACLDNG_API_TOKEN" in os.environ:
        api_key = os.environ["ACLDNG_API_TOKEN"]
    else:
        api_key = pathlib.Path("/usr/local/etc/acld-ng-apitoken").read_text().strip()

    return NullRouteClient(
        request_queue=request_queue,
        ws=ws,
        api_key=api_key,
        queue_get_timeout=0.01,
    )


async def main():
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
    args = parser.parse_args()

    logging.basicConfig(level=getattr(logging, args.log_level.upper()))

    request_queue = queue.Queue()
    nullroute_client: NullRouteClient | None = None
    nullroute_thread: threading.Thread | None = None

    try:
        async with websockets.connect(
            args.ws_uri, open_timeout=args.ws_open_timeout
        ) as ws:
            LOGGER.info("Connected...")
            nullroute_client = setup_nullroute_client(args, request_queue, ws)
            nullroute_thread = threading.Thread(target=nullroute_client.run)
            nullroute_thread.start()

            proxy = Proxy(
                websocket_client=ws,
                request_topic=args.request_topic,
                request_queue=request_queue,
            )

            try:
                await proxy.run()
            except asyncio.exceptions.CancelledError:
                LOGGER.info("Cancelled...")
    finally:
        try:
            if nullroute_client is not None:
                nullroute_client.stop()
                assert nullroute_thread is not None
                nullroute_thread.join()
        except Exception as e:
            LOGGER.exception("Exception shutting down nullroute_client: %s", e)


if __name__ == "__main__":
    asyncio.run(main())
