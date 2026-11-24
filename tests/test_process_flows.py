import unittest

from scapy.all import IP, TCP

from packets import classify
from process_flows import OwnerHistory, process_groups


def record(stamp, flags, seq):
    packet = IP(src="127.0.0.1", dst="127.0.0.1") / TCP(sport=54001, dport=8000, flags=flags, seq=seq)
    packet.time = stamp
    return classify(packet)


class ProcessFlowTests(unittest.TestCase):
    def test_port_and_pid_reuse_do_not_merge_connections(self):
        records = [record(1, "S", 30), record(2, "F", 31), record(5, "S", 70), record(6, "F", 71)]
        local = records[0].endpoints[1]
        older = (1000, 0.5, "client.exe")
        newer = (1000, 4.5, "client.exe")
        history = OwnerHistory()
        history.spans[records[0].flow_key] = [(1.5, 1.8, older, local), (5.5, 5.8, newer, local)]
        groups, _ = process_groups(records, history)
        self.assertEqual([n for n, _ in groups[older][0].rows], [1, 2])
        self.assertEqual([n for n, _ in groups[newer][0].rows], [3, 4])

    def test_short_connection_without_matching_sample_stays_unknown(self):
        records = [record(2, "S", 10), record(2.03, "R", 11)]
        history = OwnerHistory()
        history.spans[records[0].flow_key] = [(1, 1.3, (99, 0, "old.exe"), records[0].endpoints[1])]
        groups, _ = process_groups(records, history)
        self.assertEqual(list(groups), [None])
        self.assertEqual(len(groups[None][0].rows), 2)
