"""Packet classification shared by the list, display filter and detail panes."""

import re
from dataclasses import dataclass
from datetime import datetime

from scapy.layers.inet import ICMP, IP, TCP, UDP
from scapy.layers.inet6 import IPv6, _ICMPv6
from scapy.packet import NoPayload, Packet


FILTERS = ("全部", "HTTP", "TCP", "UDP", "IPv4", "IPv6", "ICMP")
REQUEST = re.compile(rb"[!#$%&'*+.^_`|~0-9A-Za-z-]+ [^\x00-\x20\x7f]+ HTTP/1\.\d")
RESPONSE = re.compile(rb"HTTP/1\.\d [1-5][0-9]{2}(?: [^\r\n]*)?")


@dataclass
class Record:
    packet: Packet
    tags: set[str]
    time: str
    source: str
    destination: str
    protocol: str
    info: str
    length: int
    endpoints: tuple | None

    @property
    def flow_key(self):
        if self.endpoints:
            version, source, destination = self.endpoints
            return version, tuple(sorted((source, destination)))
        return None


def classify(packet):
    tags = set()
    layer = packet
    source = str(getattr(packet, "src", "") or "—")
    destination = str(getattr(packet, "dst", "") or "—")
    protocol = packet.name
    info = packet.summary()
    endpoints = None
    version = None
    while not isinstance(layer, NoPayload):
        if isinstance(layer, (IP, IPv6)):
            protocol = "IPv4" if isinstance(layer, IP) else "IPv6"
            source, destination = layer.src, layer.dst
            version = layer.version
        elif isinstance(layer, (ICMP, _ICMPv6)):
            tags.add("ICMP")
            protocol = "ICMPv4" if isinstance(layer, ICMP) else "ICMPv6"
            info = f"{layer.name}  type={layer.type}"
            if "code" in layer.fieldtype:
                info += f"  code={layer.code}"
            break
        elif isinstance(layer, (TCP, UDP)):
            protocol = layer.name
            tags.add(protocol)
            info = f"{layer.sport} → {layer.dport}"
            if isinstance(layer, TCP):
                if version is not None:
                    endpoints = version, (source, layer.sport), (destination, layer.dport)
                info += f"  [{layer.flags}]  seq={layer.seq}  ack={layer.ack}"
                # Scapy attaches link padding to the payload chain. Its original
                # TCP segment is already limited to the IP payload length.
                if layer.original:
                    payload = layer.original[layer.dataofs * 4:]
                else:
                    payload = bytes(layer.payload)
                first, separator, _ = payload.partition(b"\r\n")
                if separator and (REQUEST.fullmatch(first) or RESPONSE.fullmatch(first)):
                    protocol = "HTTP"
                    tags.add(protocol)
                    info = first.decode("ascii", "backslashreplace")
            break
        else:
            layer = layer.payload
            continue
        tags.add(protocol)
        layer = layer.payload
    return Record(packet, tags, datetime.fromtimestamp(float(packet.time)).strftime("%H:%M:%S.%f"),
                  source, destination, protocol, info, len(packet.original or bytes(packet)), endpoints)
