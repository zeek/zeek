# @TEST-GROUP: broker
#
# This test requires the websockets module, available via
# "pip install websockets".
# @TEST-REQUIRES: python3 -c 'import websockets'
#
# @TEST-PORT: BROKER_PORT
#
# @TEST-EXEC: btest-bg-run server "zeek -b %INPUT >output"
# @TEST-EXEC: btest-bg-run client "python3 ../client.py >output"
#
# @TEST-EXEC: btest-bg-wait 5
# @TEST-EXEC: btest-diff client/output
# @TEST-EXEC: TEST_DIFF_CANONIFIER= btest-diff server/output

redef allow_network_time_forward = F;
redef exit_only_after_terminate = T;
redef Broker::disable_ssl = T;

global event_count = 0;

global ping: event(msg: string, c: count);

event zeek_init()
    {
    # Tue 18 Apr 2023 12:13:14 PM UTC
    set_network_time(double_to_time(1681819994.0));
    Broker::subscribe("/zeek/event/my_topic");
    Broker::listen_websocket("127.0.0.1", to_port(getenv("BROKER_PORT")));
    }

function send_event()
    {
    ++event_count;
    local e = Broker::make_event(ping, "my-message", event_count);
    Broker::publish("/zeek/event/my_topic", e);
    }

event Broker::peer_added(endpoint: Broker::EndpointInfo, msg: string)
    {
    print fmt("sender added peer: endpoint=%s msg=%s", endpoint$network$address, msg);
    send_event();
    }

event Broker::peer_lost(endpoint: Broker::EndpointInfo, msg: string)
    {
    print fmt("sender lost peer: endpoint=%s msg=%s", endpoint$network$address, msg);
    terminate();
    }

event pong(msg: string, n: count) &is_used
    {
    print fmt("sender got pong: %s, %s network_time=%s current_event_time=%s",
              msg, n, network_time(), current_event_time());
    set_network_time(network_time() + 10sec);
    send_event();
    }


@TEST-START-FILE client.py
import asyncio, datetime, websockets, os, time, json, sys

ws_port = os.environ['BROKER_PORT'].split('/')[0]
ws_url = 'ws://localhost:%s/v1/messages/json' % ws_port
topic = '"/zeek/event/my_topic"'

def broker_value(type, val):
    return {
            '@data-type': type,
            'data': val
            }

async def do_run():
    # Try up to 30 times.
    connected  = False
    for i in range(30):
        try:
            ws = await websockets.connect(ws_url)
            connected  = True

            # send filter and wait for ack
            await ws.send('[%s]' % topic)
            ack_json = await ws.recv()
            ack = json.loads(ack_json)
            if not 'type' in ack or ack['type'] != 'ack':
                print('*** unexpected ACK from server:')
                print(ack_json)
                sys.exit()
        except Exception as e:
            if not connected:
                print('failed to connect to %s, try again (%s)' % (ws_url, e), file=sys.stderr)
                await asyncio.sleep(1)
                continue
            else:
                print('exception: %s' % e, file=sys.stderr)
                sys.exit()

        for round in range(3):
            # wait for ping
            msg = await ws.recv()
            msg = json.loads(msg)
            if not 'type' in msg or msg['type'] != 'data-message':
                print("unexpected type", msg)
                continue
            ping = msg['data'][2]['data']
            if len(ping) < 3:
                print("no metadata on event")
                continue

            name = ping[0]['data']
            args = [x['data'] for x in ping[1]['data']]
            metadata = ping[2]['data']
            print(name, "args", args, "metadata", metadata)

            # send pong
            dt = datetime.datetime.utcfromtimestamp(1681819994 + args[1])
            ts_str = dt.isoformat('T', 'milliseconds')
            pong = [
                broker_value('string', 'pong'),
                broker_value('vector', [
                    broker_value('string', args[0]),
                    broker_value('count', args[1]),
                ]),
                broker_value('vector', [
                    broker_value('vector', [
                        broker_value('count', 1),  # network_timestamp
                        broker_value('timestamp', ts_str),
                    ]),
                ]),
           ]

            ev = [broker_value('count', 1), broker_value('count', 1), broker_value('vector', pong)]
            msg = {
                'type': 'data-message',
                'topic': '/zeek/event/my_topic',
                '@data-type': 'vector', 'data': ev
            }

            msg = json.dumps(msg)
            await ws.send(msg)

        await ws.close()
        sys.exit()

loop = asyncio.get_event_loop()
loop.run_until_complete(do_run())

@TEST-END-FILE
