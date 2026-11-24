import sys
from queue import Empty

from PySide6.QtCore import QAbstractTableModel, QModelIndex, Qt, QTimer
from PySide6.QtGui import QAction, QFontDatabase, QKeySequence, QShortcut
from PySide6.QtWidgets import (
    QAbstractItemView, QApplication, QComboBox, QDialog, QGroupBox, QHBoxLayout, QLabel,
    QCheckBox, QLineEdit, QMainWindow, QPlainTextEdit, QPushButton, QSplitter,
    QListWidget, QStackedWidget, QTableView, QVBoxLayout, QWidget,
)
from scapy.utils import hexdump

from capture import Capture, interfaces
from packets import FILTERS
from process_flows import process_groups


class PacketTable(QAbstractTableModel):
    headers = ("序号", "时间", "源地址", "目的地址", "协议", "字节", "摘要")

    def __init__(self):
        super().__init__()
        self.records = []
        self.visible = []
        self.protocol = FILTERS[0]
        self.query = ""

    def matches(self, record):
        if self.protocol != FILTERS[0] and self.protocol not in record.tags:
            return False
        return not self.query or any(self.query in value.casefold() for value in
                                     (record.source, record.destination, record.protocol, record.info))

    def refilter(self, protocol, query):
        self.beginResetModel()
        self.protocol = protocol
        self.query = query.strip().casefold()
        self.visible = [i for i, record in enumerate(self.records) if self.matches(record)]
        self.endResetModel()

    def clear(self):
        self.beginResetModel()
        self.records.clear()
        self.visible.clear()
        self.endResetModel()

    def append(self, batch):
        indices = [i for i, record in enumerate(batch, len(self.records)) if self.matches(record)]
        self.records.extend(batch)
        if indices:
            self.beginInsertRows(QModelIndex(), len(self.visible), len(self.visible) + len(indices) - 1)
            self.visible.extend(indices)
            self.endInsertRows()

    def rowCount(self, parent=QModelIndex()):
        return 0 if parent.isValid() else len(self.visible)

    def columnCount(self, parent=QModelIndex()):
        return len(self.headers)

    def headerData(self, section, orientation, role):
        if role == Qt.ItemDataRole.DisplayRole and orientation == Qt.Orientation.Horizontal:
            return self.headers[section]

    def data(self, index, role):
        if index.isValid() and role in (Qt.ItemDataRole.DisplayRole, Qt.ItemDataRole.ToolTipRole):
            number = self.visible[index.row()]
            record = self.records[number]
            return (number + 1, record.time, record.source, record.destination,
                    record.protocol, record.length, record.info)[index.column()]


def detail_pane(title):
    box = QGroupBox(title)
    layout = QVBoxLayout(box)
    editor = QPlainTextEdit(readOnly=True)
    editor.setFont(QFontDatabase.systemFont(QFontDatabase.SystemFont.FixedFont))
    editor.setLineWrapMode(QPlainTextEdit.LineWrapMode.NoWrap)
    editor.setPlaceholderText("选择上方的数据包以查看详情")
    layout.addWidget(editor)
    return box, editor


class Window(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("网络嗅探器 · 实验 1A")
        self.resize(1160, 720)
        self.session = None
        self.owner_history = None
        self.awaiting_ready = False
        self.stop_requested = False
        self.closing = False
        self.state = "就绪"
        self.loss = 0
        self.parse_status = ""
        central = QWidget()
        self.setCentralWidget(central)
        layout = QVBoxLayout(central)
        layout.setContentsMargins(16, 14, 16, 8)
        layout.setSpacing(10)
        self.setStyleSheet("""
            QPushButton { padding: 5px 12px; }
            QPushButton#start:enabled { background: #176961; color: white;
                border: 1px solid #12574f; border-radius: 4px; }
            QPushButton#start:hover:enabled { background: #12574f; }
            QPushButton#start:focus { border: 2px solid palette(highlight); }
            QComboBox, QLineEdit { min-height: 26px; }
            QLabel#section { font-size: 16px; font-weight: bold; }
            QGroupBox { font-weight: bold; }
            QHeaderView::section { padding: 4px; }
        """)
        controls = QHBoxLayout()
        layout.addLayout(controls)
        self.device = QComboBox()
        self.start = QPushButton("开始抓包")
        self.start.setObjectName("start")
        self.start.setToolTip("开始新一轮抓包。网卡打开后将清空上一轮记录。")
        self.refresh = QPushButton("刷新网卡")
        self.refresh.clicked.connect(self.load_interfaces)
        self.stop = QPushButton("停止")
        self.stop.setEnabled(False)
        self.filter = QComboBox()
        self.filter.addItems(FILTERS)
        self.flow = QPushButton("追踪 TCP 流")
        self.flow.setEnabled(False)
        self.flow.clicked.connect(self.trace_flow)
        controls.addWidget(QLabel("抓包网卡"))
        controls.addWidget(self.device, 1)
        for widget in (self.refresh, self.start, self.stop):
            controls.addWidget(widget)

        tools = QHBoxLayout()
        layout.addLayout(tools)
        title = QLabel("数据包")
        title.setObjectName("section")
        tools.addWidget(title)
        tools.addSpacing(8)
        self.search = QLineEdit()
        self.search.setAccessibleName("搜索已抓到的数据包")
        self.search.setPlaceholderText("搜索地址、协议或摘要  (Ctrl+F)")
        self.search.setClearButtonEnabled(True)
        self.follow = QCheckBox("跟随最新")
        self.follow.setToolTip("有新的匹配记录时滚动到底部")
        tools.addWidget(QLabel("协议"))
        tools.addWidget(self.filter)
        tools.addWidget(self.search, 1)
        tools.addWidget(self.follow)
        tools.addWidget(self.flow)
        self.process_button = QPushButton("按进程查看")
        self.process_button.setEnabled(False)
        self.process_button.clicked.connect(self.show_processes)
        tools.addWidget(self.process_button)
        self.flow.setToolTip("选择 TCP 或 HTTP 数据包，查看同一流的双向记录")
        self.device.setAccessibleName("抓包网卡")
        self.filter.setAccessibleName("显示协议")
        find = QShortcut(QKeySequence.StandardKey.Find, self)
        find.activated.connect(self.focus_search)
        panes = QSplitter(Qt.Orientation.Vertical)
        layout.addWidget(panes)
        self.table = QTableView()
        self.model = PacketTable()
        self.table.setModel(self.model)
        self.table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.table.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        self.table.setAlternatingRowColors(True)
        self.table.setShowGrid(False)
        self.table.setWordWrap(False)
        self.table.setAccessibleName("数据包列表")
        copy = QAction("复制数据包摘要", self.table)
        copy.setShortcut(QKeySequence.StandardKey.Copy)
        copy.setShortcutContext(Qt.ShortcutContext.WidgetShortcut)
        copy.triggered.connect(self.copy_row)
        self.table.addAction(copy)
        self.table.setContextMenuPolicy(Qt.ContextMenuPolicy.ActionsContextMenu)
        self.table.verticalHeader().setDefaultSectionSize(26)
        self.table.verticalHeader().hide()
        self.table.horizontalHeader().setStretchLastSection(True)
        for column, width in enumerate((58, 136, 156, 156, 76, 64)):
            self.table.setColumnWidth(column, width)
        self.list_area = QStackedWidget()
        self.list_area.addWidget(self.table)
        self.empty = QLabel()
        self.empty.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.empty.setWordWrap(True)
        self.list_area.addWidget(self.empty)
        panes.addWidget(self.list_area)
        details = QSplitter()
        fields, self.fields = detail_pane("协议字段")
        binary, self.binary = detail_pane("十六进制 / ASCII")
        details.addWidget(fields)
        details.addWidget(binary)
        panes.addWidget(details)
        panes.setSizes([370, 260])
        self.filter.currentTextChanged.connect(self.refilter)
        self.search_timer = QTimer(self, interval=150, singleShot=True)
        self.search.textChanged.connect(lambda: self.search_timer.start())
        self.search_timer.timeout.connect(self.refilter)
        self.follow.toggled.connect(self.follow_latest)
        self.table.selectionModel().currentRowChanged.connect(self.show_packet)
        self.start.clicked.connect(self.begin)
        self.stop.clicked.connect(self.request_stop)
        self.timer = QTimer(self, interval=80)
        self.timer.timeout.connect(self.poll)
        self.load_interfaces()

    def load_interfaces(self):
        previous = self.device.currentData()
        try:
            available = interfaces()
            self.device.clear()
            preferred = 0
            for iface in available:
                loopback = iface.network_name.endswith("NPF_Loopback")
                label = f"本机回环 · {iface.name}" if loopback else iface.name
                self.device.addItem(label, iface.network_name)
                self.device.setItemData(self.device.count() - 1, iface.network_name, Qt.ItemDataRole.ToolTipRole)
                if loopback:
                    preferred = self.device.count() - 1
            index = self.device.findData(previous) if previous else -1
            self.device.setCurrentIndex(index if index >= 0 else preferred)
            self.state = "就绪" if available else "未发现网卡，请检查 Npcap 后刷新"
        except Exception as error:
            self.state = f"枚举网卡失败：{error}"
        self.start.setEnabled(self.device.count() > 0)
        self.status()

    def focus_search(self):
        self.search.setFocus()
        self.search.selectAll()

    def copy_row(self):
        index = self.table.currentIndex()
        if index.isValid():
            values = (index.siblingAtColumn(col).data() for col in range(self.model.columnCount()))
            QApplication.clipboard().setText("\t".join(map(str, values)))

    def follow_latest(self):
        if self.follow.isChecked() and self.model.visible:
            self.table.scrollToBottom()

    def status(self):
        if self.model.visible:
            self.list_area.setCurrentWidget(self.table)
        else:
            if self.model.records:
                hint = "没有匹配的数据包。可切换协议或清除搜索条件。"
            elif self.session and not self.stop_requested:
                hint = "正在打开网卡…" if self.awaiting_ready else "等待所选网卡上的流量…"
            elif not self.device.count():
                hint = "未找到抓包网卡。检查 Npcap 后点击「刷新网卡」。"
            else:
                hint = "选择网卡并点击「开始抓包」。本机流量请选择回环接口。"
            self.empty.setText(hint)
            self.list_area.setCurrentWidget(self.empty)
        self.statusBar().showMessage(f"{self.state}    已记录 {len(self.model.records)} 包    "
                                     f"显示 {len(self.model.visible)} 包    队列丢弃 {self.loss} 包"
                                     f"{self.parse_status}")

    def refilter(self):
        self.search_timer.stop()
        index = self.table.currentIndex()
        selected = self.model.visible[index.row()] if index.isValid() else None
        self.model.refilter(self.filter.currentText(), self.search.text())
        self.clear_details()
        self.status()
        if selected is not None and selected in self.model.visible:
            self.table.selectRow(self.model.visible.index(selected))
        else:
            self.follow_latest()

    def clear_details(self):
        self.fields.clear()
        self.binary.clear()
        self.flow.setEnabled(False)

    def show_packet(self, index, previous):
        if index.isValid():
            record = self.model.records[self.model.visible[index.row()]]
            self.flow.setEnabled(record.endpoints is not None)
            self.fields.setPlainText(record.info + "\n\n" + record.packet.show(dump=True))
            self.binary.setPlainText(hexdump(record.packet.original or bytes(record.packet), dump=True))

    def trace_flow(self):
        index = self.table.currentIndex()
        if not index.isValid():
            return
        selected = self.model.records[self.model.visible[index.row()]]
        key = selected.flow_key
        if key is None:
            return
        rows = [(number, record) for number, record in enumerate(self.model.records, 1)
                if record.flow_key == key]
        self.open_flow(key, rows)

    def open_flow(self, key, rows):
        version, (a, b) = key
        dialog = QDialog(self)
        dialog.setWindowTitle("双向 TCP 流 · 当前记录快照")
        dialog.resize(890, 420)
        layout = QVBoxLayout(dialog)
        layout.addWidget(QLabel(f"IPv{version}    A  [{a[0]}]:{a[1]}       B  [{b[0]}]:{b[1]}"))
        view = QPlainTextEdit(readOnly=True)
        view.setLineWrapMode(QPlainTextEdit.LineWrapMode.NoWrap)
        view.setFont(QFontDatabase.systemFont(QFontDatabase.SystemFont.FixedFont))
        lines = []
        for number, record in rows:
            direction = "A → B" if record.endpoints[1] == a else "B → A"
            lines.append(f"{number:6}   {record.time}   {direction}   {record.info}")
        view.setPlainText("\n".join(lines))
        layout.addWidget(view)
        dialog.setAttribute(Qt.WidgetAttribute.WA_DeleteOnClose)
        dialog.show()

    def show_processes(self):
        groups, error = process_groups(self.model.records, self.owner_history)
        dialog = QDialog(self)
        dialog.setWindowTitle("进程的 TCP 流 · 当前记录快照")
        dialog.resize(800, 430)
        layout = QVBoxLayout(dialog)
        picker = QComboBox()
        picker.setAccessibleName("本机进程")
        owners = sorted(groups, key=lambda o: (o is None, o[2].casefold() if o else "", o[0] if o else 0))
        for owner in owners:
            label = f"{owner[2]}  ·  PID {owner[0]}" if owner else "归属未知"
            picker.addItem(f"{label}  ·  {len(groups[owner])} 条流")
        layout.addWidget(picker)
        listing = QListWidget()
        listing.setAccessibleName("所选进程的 TCP 流")
        layout.addWidget(listing)
        detail = QPushButton("查看双向数据包")
        layout.addWidget(detail)
        if error:
            layout.addWidget(QLabel(f"读取系统连接表失败：{error}"))
        if None in groups:
            layout.addWidget(QLabel("归属未知表示采样期间未匹配到本机进程。"))

        def select_process(index):
            listing.clear()
            for flow in groups[owners[index]]:
                version, (a, b) = flow.key
                first = flow.rows[0][1]
                listing.addItem(f"{first.time}    IPv{version}    [{a[0]}]:{a[1]} ↔ "
                                f"[{b[0]}]:{b[1]}    {len(flow.rows)} 包")
            listing.setCurrentRow(0)

        def inspect():
            if listing.currentRow() >= 0:
                flow = groups[owners[picker.currentIndex()]][listing.currentRow()]
                self.open_flow(flow.key, flow.rows)

        picker.currentIndexChanged.connect(select_process)
        detail.clicked.connect(inspect)
        listing.itemDoubleClicked.connect(inspect)
        if owners:
            select_process(0)
        dialog.setAttribute(Qt.WidgetAttribute.WA_DeleteOnClose)
        dialog.show()

    def begin(self):
        session = Capture(self.device.currentData())
        try:
            session.sniffer.start()
        except Exception as error:
            self.state = f"启动失败：{error}"
            self.status()
            return
        self.session = session
        self.awaiting_ready = True
        self.stop_requested = False
        self.start.setEnabled(False)
        self.device.setEnabled(False)
        self.refresh.setEnabled(False)
        self.stop.setEnabled(True)
        self.state = "正在打开网卡"
        self.status()
        self.timer.start()

    def request_stop(self):
        self.stop_requested = True
        self.state = "正在停止"
        self.stop.setEnabled(False)
        self.status()

    def poll(self):
        session = self.session
        if self.awaiting_ready and session.ready.is_set():
            self.model.clear()
            self.owner_history = session.owners
            self.process_button.setEnabled(False)
            self.clear_details()
            self.awaiting_ready = False
        if self.stop_requested:
            session.stop_when_ready()
        elif session.ready.is_set():
            self.state = "正在抓包"
        if not self.awaiting_ready:
            batch = []
            for _ in range(512):
                try:
                    batch.append(session.records.get_nowait())
                except Empty:
                    break
            previous_count = len(self.model.visible)
            self.model.append(batch)
            if not self.process_button.isEnabled() and any(record.endpoints for record in batch):
                self.process_button.setEnabled(True)
            if previous_count != len(self.model.visible):
                self.follow_latest()
            self.loss = session.dropped
            self.parse_status = (f"    解析失败 {session.parse_errors} 包（最近：{session.last_parse_error}）"
                                 if session.parse_errors else "")
        if not session.sniffer.thread.is_alive() and session.records.empty():
            session.owners.done.set()
            error = session.sniffer.exception
            self.state = "已停止" if self.stop_requested else "抓包意外结束"
            if error:
                self.state = f"抓包失败：{error}"
            self.session = None
            self.timer.stop()
            self.start.setEnabled(True)
            self.device.setEnabled(True)
            self.refresh.setEnabled(True)
            self.stop.setEnabled(False)
            if self.closing:
                self.close()
        self.status()

    def closeEvent(self, event):
        if self.session:
            event.ignore()
            self.closing = True
            self.request_stop()
        else:
            event.accept()


if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = Window()
    window.show()
    sys.exit(app.exec())
