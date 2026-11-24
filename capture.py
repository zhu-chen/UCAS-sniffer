"""One background sniffer and a bounded handoff queue per capture."""

from queue import Queue
from threading import Event

from scapy.all import AsyncSniffer, conf

from packets import classify
from process_flows import OwnerHistory


def interfaces():
    conf.ifaces.reload()
    return sorted(conf.ifaces.values(), key=lambda iface: iface.name.casefold())


class Capture:
    def __init__(self, device):
        self.records = Queue(maxsize=2048)
        self.ready = Event()
        self.dropped = 0
        self.parse_errors = 0
        self.last_parse_error = ""
        self.stopping = False
        self.owners = OwnerHistory()
        self.sniffer = AsyncSniffer(iface=device, store=False, promisc=False,
                                    prn=self.receive, started_callback=self.started)

    def started(self):
        self.owners.thread.start()
        self.ready.set()

    def receive(self, packet):
        # Only the sniffer thread produces records, so a free slot stays free.
        if self.records.full():
            self.dropped += 1
            return
        # Scapy treats exceptions escaping prn as socket failures and closes
        # the capture socket. Keep a single packet's parsing failure local.
        try:
            record = classify(packet)
        except Exception as error:
            self.last_parse_error = f"{type(error).__name__}: {error}"
            self.parse_errors += 1
            return
        self.records.put_nowait(record)

    def stop_when_ready(self):
        if self.ready.is_set() and self.sniffer.running and not self.stopping:
            self.sniffer.stop(join=False)
            self.stopping = True
