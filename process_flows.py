"""Correlate captured TCP conversations with timed Windows socket-table samples."""

from collections import defaultdict
from dataclasses import dataclass, field
from ipaddress import ip_address
from threading import Event, Lock, Thread
from time import time

import psutil
from scapy.layers.inet import TCP


INTERVAL = 0.25


def endpoint(addr):
    ip = ip_address(addr.ip.split("%")[0])
    mapped = getattr(ip, "ipv4_mapped", None)
    return str(mapped or ip), addr.port


class OwnerHistory:
    def __init__(self):
        self.done = Event()
        self.lock = Lock()
        self.spans = defaultdict(list)
        self.error = ""
        self.thread = Thread(target=self.run, daemon=True, name="TCP owner sampler")

    def run(self):
        previous = {}
        while not self.done.is_set():
            try:
                stamp = time()
                rows = psutil.net_connections(kind="tcp")
                owners = {}
                observed = set()
                for row in rows:
                    if not row.raddr or not row.pid or row.status == psutil.CONN_TIME_WAIT:
                        continue
                    local, remote = endpoint(row.laddr), endpoint(row.raddr)
                    version = 6 if ":" in local[0] else 4
                    key = (version, tuple(sorted((local, remote))))
                    if row.pid not in owners:
                        try:
                            proc = psutil.Process(row.pid)
                            owners[row.pid] = (row.pid, proc.create_time(), proc.name())
                        except psutil.NoSuchProcess:
                            continue
                        except psutil.AccessDenied:
                            owners[row.pid] = (row.pid, None, "名称不可读")
                    identity = (key, owners[row.pid], local)
                    observed.add(identity)
                with self.lock:
                    current = {}
                    for identity in observed:
                        key, owner, local = identity
                        spans = self.spans[key]
                        if identity in previous:
                            index = previous[identity]
                            spans[index] = (spans[index][0], stamp, owner, local)
                        else:
                            index = len(spans)
                            spans.append((stamp, stamp, owner, local))
                        current[identity] = index
                    self.error = ""
                previous = current
            except (psutil.Error, OSError) as error:
                previous = {}
                with self.lock:
                    self.error = str(error)
            self.done.wait(INTERVAL)

    def snapshot(self, keys):
        with self.lock:
            return {key: tuple(self.spans.get(key, ())) for key in keys}, self.error


@dataclass
class Conversation:
    key: tuple
    opening: tuple | None
    rows: list = field(default_factory=list)
    closed: bool = False


def process_groups(records, history):
    conversations = defaultdict(list)
    for number, record in enumerate(records, 1):
        key = record.flow_key
        if key is None:
            continue
        tcp = record.packet[TCP]
        opening = (record.endpoints[1], tcp.seq) if int(tcp.flags) & 0x12 == 2 else None
        streams = conversations[key]
        if not streams or (opening and (streams[-1].opening != opening or streams[-1].closed)):
            streams.append(Conversation(key, opening))
        flow = streams[-1]
        flow.rows.append((number, record))
        if int(tcp.flags) & 5:
            flow.closed = True

    spans, error = history.snapshot(conversations)
    groups = defaultdict(list)
    for key, streams in conversations.items():
        for i, flow in enumerate(streams):
            first = float(flow.rows[0][1].packet.time)
            last = float(flow.rows[-1][1].packet.time)
            # Allow one sampling interval at open edges, never across another
            # observed handshake or beyond an observed close.
            begin = first if flow.opening or i else first - INTERVAL
            end = last if flow.closed or i + 1 < len(streams) else last + INTERVAL
            matched = {(owner, local) for start, stop, owner, local in spans[key]
                       if start <= end and stop >= begin}
            for owner in {owner for owner, _ in matched} or {None}:
                groups[owner].append(flow)
    return groups, error
