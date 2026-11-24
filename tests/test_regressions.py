import unittest
from unittest.mock import Mock, patch

from PySide6.QtWidgets import QApplication
from scapy.all import Ether, IP, Raw, TCP
from scapy.layers.inet6 import (
    IPv6, ICMPv6EchoRequest, ICMPv6MLReport2, ICMPv6MRD_Advertisement,
    ICMPv6MRD_Solicitation, ICMPv6MRD_Termination,
)

from capture import Capture
from main import Window
from packets import classify


def http_frame(payload, padding=b""):
    frame = Ether(dst="00:00:00:00:00:01") / IP() / TCP(dport=8000) / Raw(payload)
    return Ether(bytes(frame) + padding)


class CaptureRegressions(unittest.TestCase):
    def test_icmpv6_subtypes_with_and_without_code(self):
        for message in (ICMPv6MLReport2(), ICMPv6MRD_Advertisement(),
                        ICMPv6MRD_Solicitation(), ICMPv6MRD_Termination(), ICMPv6EchoRequest()):
            with self.subTest(message=message.name):
                packet = IPv6(bytes(IPv6(src="::1", dst="::1") / message))
                record = classify(packet)
                self.assertEqual(record.tags, {"IPv6", "ICMP"})
                self.assertIn(f"type={message.type}", record.info)
                self.assertEqual("code=0" in record.info, isinstance(message, ICMPv6EchoRequest))

    def test_packet_error_does_not_interrupt_capture_callback(self):
        session = Capture(None)
        frame = http_frame(b"GET /after-error HTTP/1.1\r\n")
        with patch("capture.classify", side_effect=ValueError("sample error")):
            session.receive(frame)
        session.receive(frame)
        self.assertEqual(session.parse_errors, 1)
        self.assertIn("sample error", session.last_parse_error)
        self.assertEqual(session.dropped, 0)
        self.assertEqual(session.records.get_nowait().info, "GET /after-error HTTP/1.1")

    def test_only_tcp_bytes_complete_http_line(self):
        line = b"GET /lab HTTP/1.1"
        partial = classify(http_frame(line, padding=b"\r\n"))
        complete = classify(http_frame(line + b"\r\n", padding=b"\x00"))
        self.assertEqual(partial.tags, {"IPv4", "TCP"})
        self.assertEqual(complete.tags, {"IPv4", "TCP", "HTTP"})
        self.assertEqual(complete.info, "GET /lab HTTP/1.1")

    def test_full_queue_skips_parsing_then_resumes(self):
        session = Capture(None)
        for _ in range(session.records.maxsize):
            session.records.put_nowait(None)
        with patch("capture.classify") as parse:
            session.receive(None)
            parse.assert_not_called()
            session.records.get_nowait()
            session.receive(None)
            parse.assert_called_once_with(None)
        self.assertEqual(session.dropped, 1)
        self.assertTrue(session.records.full())

    def test_failed_start_preserves_selection_and_success_replaces_records(self):
        app = QApplication.instance() or QApplication([])
        with patch("main.interfaces", return_value=[]):
            window = Window()
        self.addCleanup(window.close)
        window.device.addItem("test", "test")
        old = classify(http_frame(b"GET /old HTTP/1.1\r\n"))
        window.model.append([old])
        window.filter.setCurrentText("HTTP")
        window.table.selectRow(0)
        window.loss = 3
        session = Capture(None)
        session.sniffer = Mock(exception=OSError("open failed"))
        session.sniffer.thread.is_alive.return_value = False
        with patch("main.Capture", return_value=session):
            window.begin()
            window.poll()
            self.assertIn("open failed", window.state)
            self.assertEqual(window.model.records, [old])
            self.assertIn("/old", window.fields.toPlainText())
            self.assertEqual(window.loss, 3)
            window.begin()
            session.ready.set()
            session.sniffer.exception = None
            new = classify(http_frame(b"GET /new HTTP/1.1\r\n"))
            session.records.put(new)
            window.poll()
            self.assertEqual(window.model.records, [new])
            self.assertEqual(window.model.visible, [0])
            self.assertFalse(window.fields.toPlainText())
            self.assertEqual(window.loss, 0)
        app.processEvents()

    def test_search_and_protocol_preserve_matching_packet(self):
        app = QApplication.instance() or QApplication([])
        with patch("main.interfaces", return_value=[]):
            window = Window()
        self.addCleanup(window.close)
        for path in (b"/one", b"/Two"):
            window.model.append([classify(http_frame(b"GET " + path + b" HTTP/1.1\r\n"))])
        window.status()
        window.table.selectRow(1)
        window.search.setText("/two")
        window.filter.setCurrentText("TCP")
        self.assertEqual(window.model.visible, [1])
        self.assertEqual(window.table.currentIndex().row(), 0)
        self.assertIn("/Two", window.fields.toPlainText())
        window.filter.setCurrentText("UDP")
        self.assertIs(window.list_area.currentWidget(), window.empty)
        self.assertFalse(window.flow.isEnabled())
        window.search.clear()
        window.filter.setCurrentIndex(0)
        self.assertEqual(window.model.visible, [0, 1])
        app.processEvents()
