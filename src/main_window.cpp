#include "flowlens/main_window.hpp"
#include "flowlens/pcap_file.hpp"
#include <QtWidgets>
#include <algorithm>
#include <fstream>
#include <sstream>
#include <set>

namespace fl {
namespace {
QString qs(const std::string& s) {
    return QString::fromUtf8(s.data(), int(s.size()));
}
std::string pathBytes(const QString& s) {
    return QFile::encodeName(s).toStdString();
}
QString number(uint64_t n) {
    return QLocale().toString(qulonglong(n));
}
QString sizeText(uint64_t n) {
    return n < 1024          ? QString::number(n) + " B"
           : n < 1024 * 1024 ? QString::number(n / 1024.0, 'f', 1) + " KB"
                             : QString::number(n / (1024.0 * 1024), 'f', 2) + " MB";
}
QColor protocolColor(const std::string& s) {
    if (s == "HTTP")
        return QColor("#087f8c");
    if (s == "DNS")
        return QColor("#7954bc");
    if (s == "TLS")
        return QColor("#b47723");
    if (s == "TCP")
        return QColor("#3568a0");
    if (s == "ARP")
        return QColor("#a25c38");
    return QColor("#64748b");
}
QLabel* label(const QString& text, const char* name = nullptr) {
    auto* w = new QLabel(text);
    if (name)
        w->setObjectName(name);
    return w;
}
QPushButton* button(const QString& text, const char* name = nullptr) {
    auto* b = new QPushButton(text);
    b->setCursor(Qt::PointingHandCursor);
    if (name)
        b->setObjectName(name);
    return b;
}
QString exportPath(QWidget* parent, const QString& title, const QString& name, const QString& filter) {
    if (qApp->property("headlessValidation").toBool()) return qApp->property("validationExportPath").toString();
    return QFileDialog::getSaveFileName(parent, title, name, filter);
}
QTableWidget* table(const QStringList& titles) {
    auto* t = new QTableWidget(0, titles.size());
    t->setHorizontalHeaderLabels(titles);
    t->setSelectionBehavior(QAbstractItemView::SelectRows);
    t->setSelectionMode(QAbstractItemView::SingleSelection);
    t->setEditTriggers(QAbstractItemView::NoEditTriggers);
    t->verticalHeader()->hide();
    t->horizontalHeader()->setStretchLastSection(true);
    t->horizontalHeader()->setDefaultAlignment(Qt::AlignLeft | Qt::AlignVCenter);
    t->setShowGrid(false);
    t->setAlternatingRowColors(true);
    return t;
}
void cell(QTableWidget* t, int r, int c, const QString& v) {
    auto* it = new QTableWidgetItem(v);
    t->setItem(r, c, it);
}
class Timeline : public QWidget {
    std::shared_ptr<Flow> flow_;

  public:
    explicit Timeline(std::shared_ptr<Flow> f) : flow_(std::move(f)) {
        setMinimumSize(690, std::max(320, int(std::min(size_t(32), flow_->events.size())) * 40 + 95));
    }
    void paintEvent(QPaintEvent*) override {
        QPainter p(this);
        p.setRenderHint(QPainter::Antialiasing);
        p.fillRect(rect(), QColor("#ffffff"));
        const int x1 = 200, x2 = width() - 200;
        p.setPen(QColor("#64748b"));
        p.drawText(QRect(0, 8, width() / 2, 36), Qt::AlignCenter, qs(endpoint(flow_->a, flow_->portA)));
        p.drawText(QRect(width() / 2, 8, width() / 2, 36), Qt::AlignCenter,
                   qs(endpoint(flow_->b, flow_->portB)));
        p.setPen(QPen(QColor("#cbd5e1"), 1, Qt::DashLine));
        p.drawLine(x1, 47, x1, height() - 20);
        p.drawLine(x2, 47, x2, height() - 20);
        int y = 75;
        for (size_t i = 0; i < std::min(size_t(32), flow_->events.size()); i++) {
            const auto& e = flow_->events[i];
            int from = e.reverse ? x2 : x1, to = e.reverse ? x1 : x2;
            auto color = e.reverse ? QColor("#7954bc") : QColor("#087f8c");
            p.setPen(QPen(color, 2));
            p.drawLine(from, y, to, y);
            int sign = to > from ? 1 : -1;
            p.drawLine(to, y, to - sign * 8, y - 5);
            p.drawLine(to, y, to - sign * 8, y + 5);
            p.setPen(QColor("#334155"));
            p.drawText(QRect(std::min(x1, x2) + 4, y - 23, std::abs(x2 - x1) - 8, 22), Qt::AlignCenter,
                       QString("#%1  %2   %3 bytes").arg(e.packetId).arg(qs(e.flags)).arg(e.payload));
            p.setPen(QColor("#94a3b8"));
            p.drawText(12, y + 4, QString::number((e.time - flow_->firstNs) / 1e6, 'f', 3) + " ms");
            y += 40;
        }
    }
};
} // namespace
int PacketModel::rowCount(const QModelIndex& parent) const {
    return parent.isValid() ? 0 : int(packets.size());
}
int PacketModel::columnCount(const QModelIndex& parent) const {
    return parent.isValid() ? 0 : 9;
}
QVariant PacketModel::headerData(int s, Qt::Orientation o, int role) const {
    if (o != Qt::Horizontal || role != Qt::DisplayRole)
        return {};
    return QStringList{"序号", "相对时间", "源地址", "目的地址", "协议", "长度", "进程 / PID", "流", "摘要"}
        .value(s);
}
QVariant PacketModel::data(const QModelIndex& i, int role) const {
    if (!i.isValid() || i.row() >= int(packets.size()))
        return {};
    const auto& p = packets[size_t(i.row())];
    if (role == Qt::ToolTipRole) {
        QString text = qs(p.info);
        if (i.column() == 6) {
            text += p.pid ? "\n原包 PID：连接表直接匹配" : "\n原包 PID：未直接匹配";
            for (const auto& owner : p.flowProcesses)
                text += "\n同一 TCP 会话关联：" + QString::number(owner.first) + " / " + qs(owner.second);
            text += "\npid / process 过滤包含已确认会话；不会改写原包 PID。";
        }
        for (const auto& w : p.warnings)
            text += "\n⚠ " + qs(w);
        return text;
    }
    if (role == Qt::ForegroundRole) {
        if (i.column() == 4)
            return protocolColor(p.protocol);
        if (!p.warnings.empty())
            return QColor("#b45309");
        return QColor("#334155");
    }
    if (role == Qt::BackgroundRole && p.protocol == "HTTP")
        return QColor("#effaf8");
    if (role == Qt::TextAlignmentRole)
        return int(i.column() == 0 || i.column() == 5 || i.column() == 7 ? Qt::AlignRight | Qt::AlignVCenter
                                                                         : Qt::AlignLeft | Qt::AlignVCenter);
    if (role != Qt::DisplayRole)
        return {};
    switch (i.column()) {
    case 0:
        return qulonglong(p.id);
    case 1:
        return p.timestampAvailable ? QString::number(p.timestampNs >= firstTimestamp ?
            double(p.timestampNs - firstTimestamp) / 1e9 : -double(firstTimestamp - p.timestampNs) / 1e9, 'f', 6)
                                    : QString("未提供");
    case 2:
        return qs(p.source);
    case 3:
        return qs(p.destination);
    case 4:
        return qs(p.protocol);
    case 5:
        return qulonglong(p.originalLength);
    case 6: {
        if (p.pid) return qs(p.process) + " / " + QString::number(p.pid) +
                           (p.peerPid ? " ↔ " + QString::number(p.peerPid) : "");
        QStringList owners;
        for (const auto& owner : p.flowProcesses) owners << QString::number(owner.first);
        return owners.isEmpty() ? QString("—") : "会话关联 / " + owners.join(" ↔ ");
    }
    case 7:
        return p.flowId ? QString::number(p.flowId) : QString("—");
    default:
        return qs(p.info);
    }
}
void PacketModel::append(std::vector<Packet>&& batch) {
    if (batch.empty())
        return;
    int start = int(packets.size());
    beginInsertRows(QModelIndex(), start, start + int(batch.size()) - 1);
    for (auto& p : batch) {
        if (!hasTimestamp && p.timestampAvailable) { firstTimestamp = p.timestampNs; hasTimestamp = true; }
        packets.push_back(std::move(p));
    }
    endInsertRows();
}
void PacketModel::reset() {
    beginResetModel();
    packets.clear();
    hasTimestamp = false; firstTimestamp = 0;
    endResetModel();
}
bool PacketProxy::filterAcceptsRow(int row, const QModelIndex&) const {
    auto* m = static_cast<PacketModel*>(sourceModel());
    return row >= 0 && size_t(row) < m->packets.size() && filter.matches(m->packets[size_t(row)]);
}

MainWindow::MainWindow() : model_(new PacketModel(this)), proxy_(new PacketProxy(this)) {
    setWindowTitle("FlowLens 网络协议分析器");
    resize(1660, 940);
    setMinimumSize(1280, 720);
    setStyleSheet(R"(
      QWidget { font-family:'Microsoft YaHei UI'; font-size:12px; color:#20364e; }
      QMainWindow, QWidget#workspace { background:#f5f7fa; }
      QMenuBar { background:#182e46; color:#f1f5f9; padding:2px 8px; }
      QMenuBar::item { color:#f1f5f9; background:transparent; padding:6px 11px; }
      QMenuBar::item:selected { background:#2b4b67; }
      QMenu { background:#ffffff; border:1px solid #b9c8d6; }
      QMenu::item { padding:6px 22px; }
      QMenu::item:selected { background:#deefed; }
      QToolBar { background:#233d56; border:0; spacing:6px; padding:7px 8px; }
      QToolBar QLabel { color:#e4edf5; }
      QPushButton { border:1px solid #bac8d6; border-radius:3px; background:#ffffff; padding:4px 10px; min-height:20px; }
      QPushButton:hover { background:#eaf3fa; border-color:#5c8aa9; }
      QPushButton#primary { background:#147d76; color:#ffffff; border-color:#147d76; }
      QPushButton#primary:hover { background:#0c6963; }
      QPushButton:disabled { background:#e9edf1; color:#96a3ae; border-color:#d0d9e0; }
      QPushButton#primary:disabled { background:#d6e3e5; color:#758c91; border-color:#bccfd2; }
      QLineEdit,QComboBox { background:#ffffff; color:#20364e; border:1px solid #bbcbd8; border-radius:3px; padding:4px 7px; min-height:20px; }
      QLineEdit:focus,QComboBox:focus { border:1px solid #198b81; }
      QComboBox QAbstractItemView { background:white; color:#20364e; selection-background-color:#9ecdc5; selection-color:#20364e; }
      QTabBar::tab { background:#e9eef4; color:#466079; padding:8px 24px; border-bottom:2px solid #d2dde7; }
      QTabBar::tab:selected { background:#ffffff; color:#08746c; border-bottom:2px solid #148b7e; }
      QLabel#subtitle { color:#637a8e; font-size:11px; padding:2px 0; }
      QLabel#paneHeader { background:#e4ecf4; color:#294762; padding:6px 8px; border-bottom:1px solid #c7d5e1; font-weight:600; }
      QTableView,QTableWidget,QTreeWidget,QPlainTextEdit { background:#ffffff; border:1px solid #d2dce5; color:#20364e; alternate-background-color:#f5f8fb; selection-background-color:#d7eaf5; selection-color:#143854; }
      QHeaderView::section { background:#edf2f7; color:#49627b; border:0; border-right:1px solid #dce4ec; border-bottom:1px solid #cbd8e3; padding:6px 5px; }
      QTableView::item { padding:2px 4px; }
      QTreeView::item { padding:2px 0; }
      QPlainTextEdit { font-family:'Consolas'; font-size:12px; }
      QSplitter::handle { background:#d9e3ec; width:5px; height:5px; }
      QSplitter::handle:hover { background:#95b9c6; }
      QStatusBar { background:#e4ecf4; border-top:1px solid #c7d5e1; }
      QStatusBar QLabel { color:#405a72; font-size:11px; }
      QStatusBar::item { border:0; }
      QTabWidget::pane { border:1px solid #ccd8e3; background:#ffffff; }
      QScrollBar:vertical { width:11px; background:#f1f5f8; }
      QScrollBar::handle:vertical { background:#b8c8d5; min-height:28px; }
      QLabel#caption { background:#e4ecf4; color:#294762; padding:6px; }
    )");
    auto* root = new QWidget;
    root->setObjectName("workspace");
    auto* layout = new QVBoxLayout(root);
    layout->setContentsMargins(8, 5, 8, 3);
    layout->setSpacing(5);
    setCentralWidget(root);
    auto* captureTools = addToolBar("捕获工具");
    captureTools->setMovable(false);
    captureTools->setObjectName("captureToolbar");
    auto* open = button("打开");
    auto* save = button("保存 PCAP");
    captureTools->addWidget(open); captureTools->addWidget(save); captureTools->addSeparator();
    captureTools->addWidget(label("网卡"));
    adapters_ = new QComboBox;
    adapters_->setObjectName("adapterChoice");
    adapters_->setMaxVisibleItems(8);
    adapters_->setMinimumWidth(240); adapters_->setMaximumWidth(390);
    captureTools->addWidget(adapters_);
    auto* refresh = button("刷新"); captureTools->addWidget(refresh);
    captureTools->addWidget(label("BPF"));
    captureFilter_ = new QLineEdit;
    captureFilter_->setObjectName("captureFilter");
    captureFilter_->setMinimumWidth(190);
    captureFilter_->setPlaceholderText("捕获过滤器，例如 tcp or udp");
    captureTools->addWidget(captureFilter_);
    start_ = button("开始", "primary"); stop_ = button("停止"); stop_->setEnabled(false);
    captureTools->addWidget(start_); captureTools->addWidget(stop_);
    navigation_ = new QTabBar;
    navigation_->setObjectName("navigation"); navigation_->setExpanding(false);
    for (const auto& name : {"数据包", "TCP 会话", "进程", "统计", "帮助"}) navigation_->addTab(QString::fromUtf8(name));
    layout->addWidget(navigation_);

    pages_ = new QStackedWidget;
    layout->addWidget(pages_, 1);
    auto* packetPage = new QWidget;
    auto* pl = new QVBoxLayout(packetPage);
    pl->setContentsMargins(0, 0, 0, 0);
    pl->setSpacing(4);
    auto* filterRow = new QHBoxLayout;
    filterRow->addWidget(label("显示过滤"));
    displayFilter_ = new QLineEdit;
    displayFilter_->setObjectName("displayFilter");
    displayFilter_->setPlaceholderText("http or dns  ·  tcp and port == 18080  ·  pid == 1234");
    filterRow->addWidget(displayFilter_, 1);
    auto* apply = button("应用", "primary");
    auto* clear = button("清除");
    auto* follow = button("追踪 TCP 流");
    filterRow->addWidget(apply);
    filterRow->addWidget(clear);
    filterRow->addWidget(follow);
    pl->addLayout(filterRow);
    hint_ = label("实时抓包需要 Npcap；也可打开 samples/showcase.pcap 进行离线分析。", "subtitle");
    hint_->setWordWrap(true);
    pl->addWidget(hint_);
    packetSplit_ = new QSplitter(Qt::Horizontal);
    packetSplit_->setObjectName("packetSplitter");
    packetSplit_->setChildrenCollapsible(false);
    auto pane = [](const QString& name, QWidget* child) {
        auto* container = new QWidget;
        auto* row = new QVBoxLayout(container); row->setContentsMargins(0, 0, 0, 0); row->setSpacing(0);
        row->addWidget(label(name, "paneHeader")); row->addWidget(child, 1);
        container->setMinimumWidth(180);
        return container;
    };
    proxy_->setSourceModel(model_);
    packets_ = new QTableView;
    packets_->setObjectName("packetView");
    packets_->setModel(proxy_);
    packets_->setSelectionBehavior(QAbstractItemView::SelectRows);
    packets_->setSelectionMode(QAbstractItemView::SingleSelection);
    packets_->setAlternatingRowColors(true);
    packets_->setShowGrid(false);
    packets_->verticalHeader()->hide();
    packets_->verticalHeader()->setDefaultSectionSize(24);
    packets_->setWordWrap(false);
    packets_->horizontalHeader()->setStretchLastSection(true);
    packets_->setSortingEnabled(false);
    const int widths[] = {44, 82, 136, 136, 60, 49, 105, 35, 290};
    for (int i = 0; i < 9; i++)
        packets_->setColumnWidth(i, widths[i]);
    packetSplit_->addWidget(pane("包列表", packets_));
    fields_ = new QTreeWidget;
    fields_->setObjectName("fieldTree");
    fields_->setHeaderLabels({"协议 / 字段", "值"});
    fields_->setColumnWidth(0, 175);
    fields_->setMinimumWidth(180);
    packetSplit_->addWidget(pane("字段树", fields_));
    auto* bytePane = new QWidget;
    auto* byteLayout = new QVBoxLayout(bytePane); byteLayout->setContentsMargins(0, 0, 0, 0); byteLayout->setSpacing(0);
    auto* byteHeader = new QHBoxLayout;
    byteHeader->addWidget(label("字节", "paneHeader"));
    byteView_ = new QComboBox; byteView_->setObjectName("byteView");
    byteView_->addItems({"原始帧", "重组数据报"}); byteView_->setEnabled(false);
    byteView_->setToolTip("原始帧用于保存；有完整 IP 重组结果时可切换字段和字节视图。");
    byteHeader->addWidget(byteView_, 1); byteLayout->addLayout(byteHeader);
    hex_ = new QPlainTextEdit;
    hex_->setObjectName("rawBytes");
    hex_->setReadOnly(true);
    hex_->setLineWrapMode(QPlainTextEdit::NoWrap);
    hex_->setFont(QFont("Consolas", 10));
    byteLayout->addWidget(hex_, 1);
    bytePane->setMinimumWidth(250); packetSplit_->addWidget(bytePane);
    packetSplit_->setStretchFactor(0, 5); packetSplit_->setStretchFactor(1, 3); packetSplit_->setStretchFactor(2, 3);
    packetSplit_->setSizes({790, 435, 410});
    pl->addWidget(packetSplit_, 1);
    detailTitle_ = label("选择数据包查看协议字段与原始字节", "subtitle");
    pl->addWidget(detailTitle_);
    pages_->addWidget(packetPage);
    auto* flowPage = new QWidget;
    auto* fl = new QVBoxLayout(flowPage);
    fl->setContentsMargins(0, 0, 0, 0);
    fl->addWidget(label("双击会话查看重组内容与通信时序；连接复用会生成新的流编号。", "subtitle"));
    conversations_ =
        table({"流", "端点 A", "端点 B", "应用", "包数", "总字节", "状态", "PID", "重传字节 / 缺口"});
    conversations_->setColumnWidth(1, 205);
    conversations_->setColumnWidth(2, 205);
    fl->addWidget(conversations_);
    pages_->addWidget(flowPage);
    auto* processPage = new QWidget;
    auto* pr = new QVBoxLayout(processPage);
    pr->setContentsMargins(0, 0, 0, 0);
    pr->addWidget(
        label("按连接表确认会话归属；双击进程查看其整条 TCP 会话。原包 PID 与会话关联分别保留，未观察到的短连接仍可能未知。",
              "subtitle"));
    processes_ = table({"PID", "进程名称", "关联 TCP 流", "包数", "总字节", "对端"});
    processes_->setColumnWidth(1, 210);
    pr->addWidget(processes_);
    pages_->addWidget(processPage);
    auto* statPage = new QWidget;
    auto* st = new QVBoxLayout(statPage);
    st->setContentsMargins(0, 0, 0, 0);
    protocols_ = table({"协议", "数据包", "占比", "分布"});
    protocols_->setMaximumHeight(350);
    st->addWidget(protocols_);
    diagnostics_ = new QPlainTextEdit;
    diagnostics_->setReadOnly(true);
    st->addWidget(diagnostics_, 1);
    pages_->addWidget(statPage);
    auto* help = new QTextBrowser;
    help->setOpenExternalLinks(true);
    help->setHtml(QString::fromUtf8(R"(
      <h2>流镜 FlowLens 使用与设计</h2>
      <p>本程序实现真实网络捕获、分层解析、协议过滤、TCP 会话追踪及 Windows 进程关联。界面中的离线样例均为自行生成的实验流量。</p>
      <h3>开始</h3><p>安装 Npcap 后重启本程序，选择正在使用的网卡，点击开始。必要时以管理员身份运行。测试本机服务时选择 loopback 网卡。</p>
      <h3>两种过滤</h3><p>捕获过滤器使用 libpcap BPF 语法，例如 <code>tcp port 18080</code>，在开始前设置。显示过滤器在已解析数据中查找，支持 <code>and / or / not</code>、括号和比较。</p>
      <pre>http or dns<br>tcp and (port == 18080 or ipv6)<br>ip.addr == 192.0.2.10<br>http.host contains "lab.example"<br>pid == 1234<br>malformed</pre>
      <h3>抓包层次与分析层次</h3><p>捕获提供指定链路类型的原始字节。解析逐层解释链路层、网络层、传输层和应用层。应用层消息可能跨多个 TCP 段；流重组后才有足够信息识别 HTTP。端口是线索，不是协议的充分证据。</p>
      <h3>进程筛选与关联来源</h3><p>pid / process 过滤同时匹配直接观察到的进程，以及同一 TCP 会话后续确认的所有者，因此早到的握手包也能随整条会话筛出。原包 PID / peer PID 仍只表示连接表直接匹配；会话补全显示“会话关联”，JSON 使用独立 flow_processes 字段，CSV 使用 FlowPIDs。关联按会话编号、端点、接口和节隔离；从未观察到归属的短连接或离线 PCAP 仍保持未知。</p>
      <h3>HTTPS 的边界</h3><p>抓到 TLS 流量不等于获得解密密钥。本程序显示可观察的 TLS 记录元数据，不解密 HTTPS 正文。安装根证书并配合代理的解析方式，与直接抓取网络帧所处的层次和信任机制不同。</p>
      <h3>校验和模式</h3><p>分析菜单提供自动、严格和捕获可能使用卸载三种模式；选择在下次打开文件或开始捕获时生效。自动模式对回环及已知实时捕获卸载的不确定结果显示 not available；严格模式按完整字节验证。IPv4 UDP 零校验和表示未启用，IPv6 UDP 零校验和不合法。截断、未完整重组或路由目的地址不确定时不误判为校验失败。</p>
      <h3>文件与三栏视图</h3><p>打开支持经典 PCAP，以及 PCAPNG 的节头、接口描述、增强包、简单包和旧包块。多接口和多节分别保留，时间统一为纳秒；简单包没有时间戳时显示未提供。包列表、字段树、字节栏可拖动调整比例；视图菜单可复位布局和选择列。完成 IP 重组后，字节栏可切换原始帧与重组数据报，保存 PCAP 仍使用原始帧。</p>
      <h3>独立 Wireshark 插件</h3><p>源码位于 wireshark-plugin/flowlens_companion.lua，安装方法见同目录 README.md。复制单个 Lua 文件到 Wireshark 个人 Lua 插件目录后，进入 Tools / FlowLens / TCP 会话汇总；该插件独立于本程序，不改变本程序的解析结果。运行时下载缓存 .runtime 不属于交付内容。</p>
      <h3>资源与限制</h3><p>数据包明细最多保留 20000 条，捕获队列最多 5000 条；流表最多保留 512 条，每方向重组 128 KiB，全局重组预算 32 MiB。达到上限会显示截断/淘汰提示。支持有界 IPv4 / IPv6 分片重组和 PCAPNG 读取。IP 重组最多 256 组、每组载荷 65535 字节 / 512 片、总缓存 8 MiB、TTL 30 秒；重叠冲突整组丢弃。不支持 IPv6 巨型数据报、HTTP/2、QUIC 解码或 TLS 解密。IPv4 / TCP / UDP / ICMP 校验和显示 verified、incorrect 或 not available；卸载和回环不确定时不会误报错误。</p>
      <p>字段树与原始字节一一对应；完整 IP 重组后可切换查看重组数据报。PCAPNG 只读，导出经典 PCAP 不保留接口等容器元数据，缺失时间戳或混合链路类型时会拒绝保存。依赖信息：<a href="https://npcap.com/guide/">Npcap</a> · <a href="https://doc.qt.io/">Qt</a></p>
    )"));
    pages_->addWidget(help);
    demoCaption_ = label("", "caption");
    demoCaption_->hide();
    layout->addWidget(demoCaption_);
    footer_ = label("就绪", "subtitle");
    mode_ = label("未开始", "mode"); statusBar()->addWidget(mode_); statusBar()->addWidget(footer_, 1);
    const QStringList metricNames = {"包", "TCP 流", "HTTP / DNS", "采集丢包"};
    for (int i = 0; i < 4; ++i) {
        statusBar()->addPermanentWidget(label(metricNames[i])); counters_[i] = label("0");
        statusBar()->addPermanentWidget(counters_[i]);
    }
    auto* json = button("JSON"); auto* csv = button("CSV");
    captureTools->addSeparator(); captureTools->addWidget(json); captureTools->addWidget(csv);
    auto action = [this](QMenu* menu, const QString& name, const QKeySequence& shortcut, QPushButton* target) {
        auto* a = menu->addAction(name); a->setShortcut(shortcut);
        connect(a, &QAction::triggered, target, &QPushButton::click); return a;
    };
    auto* fileMenu = menuBar()->addMenu("文件");
    action(fileMenu, "打开 PCAP / PCAPNG…", QKeySequence::Open, open);
    action(fileMenu, "保存原始报文为 PCAP…", QKeySequence::Save, save);
    action(fileMenu, "导出当前结果为 JSON…", {}, json);
    action(fileMenu, "导出当前结果为 CSV…", {}, csv);
    fileMenu->addSeparator(); connect(fileMenu->addAction("退出"), &QAction::triggered, this, &QWidget::close);
    auto* captureMenu = menuBar()->addMenu("捕获");
    action(captureMenu, "开始", QKeySequence("Ctrl+E"), start_); action(captureMenu, "停止", QKeySequence("Ctrl+Shift+E"), stop_);
    action(captureMenu, "刷新网卡", {}, refresh);
    auto* analysis = menuBar()->addMenu("分析");
    action(analysis, "应用显示过滤器", QKeySequence("Ctrl+Return"), apply);
    action(analysis, "清除显示过滤器", {}, clear);
    action(analysis, "追踪所选 TCP 流", QKeySequence("Ctrl+F"), follow);
    auto* checksums = analysis->addMenu("校验和模式（下次加载 / 捕获生效）");
    auto* modes = new QActionGroup(this);
    const QStringList modeNames = {"自动识别回环与捕获卸载", "严格验证完整字节", "捕获可能使用卸载"};
    for (int i = 0; i < 3; ++i) {
        auto* a = checksums->addAction(modeNames[i]); a->setCheckable(true); modes->addAction(a); a->setChecked(i == 0);
        a->setObjectName(QString("checksumMode%1").arg(i));
        connect(a, &QAction::triggered, this, [this, i] {
            checksumMode_ = static_cast<ChecksumMode>(i);
            hint_->setText("校验和模式已设置，重新打开文件或开始新捕获后生效。");
        });
    }
    auto* view = menuBar()->addMenu("视图");
    connect(view->addAction("恢复三栏比例"), &QAction::triggered, this, [this] { packetSplit_->setSizes({790, 435, 410}); });
    auto* columns = view->addMenu("包列表列");
    for (int i = 0; i < 9; ++i) {
        auto* a = columns->addAction(model_->headerData(i, Qt::Horizontal).toString()); a->setCheckable(true); a->setChecked(true);
        connect(a, &QAction::toggled, this, [this, i](bool show) { packets_->setColumnHidden(i, !show); });
    }
    auto* helpMenu = menuBar()->addMenu("帮助");
    auto* usage = helpMenu->addAction("使用说明"); usage->setShortcut(QKeySequence::HelpContents);
    connect(usage, &QAction::triggered, this, [this] { navigation_->setCurrentIndex(4); });
    connect(byteView_, QOverload<int>::of(&QComboBox::currentIndexChanged), this, [this] { selectPacket(); });
    connect(navigation_, &QTabBar::currentChanged, this, [this](int i) { selectPage(i); });
    connect(refresh, &QPushButton::clicked, this, [this] { refreshAdapters(); });
    connect(start_, &QPushButton::clicked, this, [this] { startCapture(); });
    connect(stop_, &QPushButton::clicked, this, [this] { stopCapture(); });
    connect(open, &QPushButton::clicked, this, [this] {
        auto p = QFileDialog::getOpenFileName(this, "打开抓包文件", QString(),
                                              "抓包文件 (*.pcap *.pcapng *.cap);;所有文件 (*)");
        if (!p.isEmpty())
            loadPcap(p);
    });
    connect(save, &QPushButton::clicked, this, [this] { savePcap(); });
    connect(apply, &QPushButton::clicked, this, [this] { applyFilter(); });
    connect(displayFilter_, &QLineEdit::returnPressed, this, [this] { applyFilter(); });
    connect(clear, &QPushButton::clicked, this, [this] {
        displayFilter_->clear();
        applyFilter();
    });
    connect(follow, &QPushButton::clicked, this, [this] { followSelected(); });
    connect(packets_->selectionModel(), &QItemSelectionModel::currentRowChanged, this,
            [this] { selectPacket(); });
    connect(packets_, &QTableView::doubleClicked, this, [this] { followSelected(); });
    connect(fields_, &QTreeWidget::currentItemChanged, this, [this](QTreeWidgetItem* it, QTreeWidgetItem*) {
        if (!it)
            return;
        size_t off = it->data(0, Qt::UserRole).toULongLong(),
               len = it->data(0, Qt::UserRole + 1).toULongLong();
        QList<QTextEdit::ExtraSelection> selections;
        for (size_t i = off; i < off + std::min(size_t(2048), len) && i < size_t(hexPositions_.size()); i++) {
            QTextEdit::ExtraSelection sel;
            sel.cursor = QTextCursor(hex_->document());
            sel.cursor.setPosition(hexPositions_[int(i)]);
            sel.cursor.movePosition(QTextCursor::Right, QTextCursor::KeepAnchor, 2);
            sel.format.setBackground(QColor("#99e5d9"));
            selections.push_back(sel);
        }
        hex_->setExtraSelections(selections);
        if (off < size_t(hexPositions_.size())) {
            auto cursor = hex_->textCursor();
            cursor.setPosition(hexPositions_[int(off)]);
            hex_->setTextCursor(cursor);
            hex_->ensureCursorVisible();
        }
    });
    connect(conversations_, &QTableWidget::cellDoubleClicked, this, [this](int r, int) {
        if (auto* item = conversations_->item(r, 0))
            showFlow(item->text().toULongLong());
    });
    connect(processes_, &QTableWidget::cellDoubleClicked, this, [this](int r, int) {
        auto* item = processes_->item(r, 0);
        if (!item || item->text() == "未知")
            return;
        displayFilter_->setText("pid == " + item->text());
        applyFilter();
        navigation_->setCurrentIndex(0);
    });
    connect(json, &QPushButton::clicked, this, [this] { exportJson(); });
    connect(csv, &QPushButton::clicked, this, [this] { exportCsv(); });
    auto* timer = new QTimer(this);
    connect(timer, &QTimer::timeout, this, [this] { timerTick(); });
    timer->start(100);
    refreshAdapters();
    updateSummary();
}
MainWindow::~MainWindow() {
    capture_.stop();
}
void MainWindow::refreshAdapters() {
    if (capture_.running())
        return;
    if (qApp->property("headlessValidation").toBool()) {
        adapters_->clear(); adapters_->addItem("离屏验证：未启动捕获"); start_->setEnabled(false); return;
    }
    adapterList_ = capture_.adapters();
    adapters_->clear();
    for (const auto& a : adapterList_)
        adapters_->addItem(qs(a.description), qs(a.name));
    if (adapterList_.empty()) {
        adapters_->addItem("Npcap 未安装 / 无可用网卡");
        hint_->setText(capture_.available() ? "未发现可用网卡，请检查权限和网络适配器。"
                                            : "未检测到 Npcap。离线分析可用；实时抓包请先安装 Npcap。 ");
    }
    start_->setEnabled(!adapterList_.empty());
}
void MainWindow::showError(const QString& message) {
    if (qApp->property("headlessValidation").toBool()) {
        qWarning().noquote() << message; return;
    }
    QMessageBox::warning(this, "FlowLens", message);
}
void MainWindow::clearPacketDetails() {
    fields_->clear();
    hex_->clear();
    hex_->setExtraSelections({});
    hexPositions_.clear();
    detailTitle_->setText("选择数据包查看协议字段与原始字节");
    const QSignalBlocker block(byteView_);
    byteView_->setCurrentIndex(0);
    byteView_->setEnabled(false);
}
void MainWindow::resetSession() {
    model_->reset();
    flows_.clear();
    ipFragments_.clear();
    protocolCounts_.clear();
    totalPackets_ = totalBytes_ = firstNs_ = warningPackets_ = displayDiscarded_ = retainedBytes_ = 0;
    clearPacketDetails();
    displayFilter_->clear();
    std::string e;
    proxy_->filter.compile("", e);
    proxy_->apply();
    conversations_->setRowCount(0);
    processes_->setRowCount(0);
    updateSummary();
}
void MainWindow::startCapture() {
    int row = adapters_->currentIndex();
    if (row < 0 || size_t(row) >= adapterList_.size())
        return;
    if (!capture_.start(adapterList_[size_t(row)].name, captureFilter_->text().toStdString())) {
        showError(qs(capture_.error()));
        return;
    }
    resetSession();
    offline_ = false;
    wasRunning_ = true;
    resolver_.refresh();
    start_->setEnabled(false);
    stop_->setEnabled(true);
    adapters_->setEnabled(false);
    captureFilter_->setEnabled(false);
    mode_->setText("正在实时捕获");
    hint_->setText("捕获中 · 点击停止后可保存 PCAP、导出结果或追踪 TCP 流。");
    updateSummary();
}
void MainWindow::stopCapture() {
    capture_.stop();
    auto remaining = capture_.take(5000);
    append(std::move(remaining));
    ipFragments_.finish();
    start_->setEnabled(!adapterList_.empty());
    stop_->setEnabled(false);
    adapters_->setEnabled(true);
    captureFilter_->setEnabled(true);
    mode_->setText("捕获已停止");
    wasRunning_ = false;
    updateSummary();
}
void MainWindow::timerTick() {
    tick_++;
    if (!offline_) {
        if (capture_.running()) ipFragments_.expire(uint64_t(QDateTime::currentMSecsSinceEpoch()) * 1000000ULL);
        if (tick_ % 5 == 0)
            resolver_.refresh();
        auto batch = capture_.take();
        append(std::move(batch));
        if (wasRunning_ && !capture_.running()) {
            stopCapture();
            if (!capture_.error().empty())
                hint_->setText(qs(capture_.error()));
        }
    }
    if (tick_ % 10 == 0) {
        updateSummary();
        if (pages_->currentIndex() == 1)
            refreshFlows();
        if (pages_->currentIndex() == 2)
            refreshProcesses();
        if (pages_->currentIndex() == 3)
            refreshStatistics();
    }
}
void MainWindow::append(std::vector<Packet>&& batch) {
    std::vector<Packet> retained;
    retained.reserve(batch.size());
    for (auto& p : batch) {
        p.id = ++totalPackets_;
        if (!firstNs_)
            firstNs_ = p.timestampNs;
        if (checksumMode_ != ChecksumMode::Automatic) p.checksumMode = checksumMode_;
        parse(p);
        ipFragments_.ingest(p);
        if (!offline_)
            resolver_.attach(p);
        flows_.ingest(p);
        totalBytes_ += p.originalLength;
        protocolCounts_[p.protocol]++;
        warningPackets_ += !p.warnings.empty();
        size_t packetBytes = p.bytes.size() + (p.reassembled ? p.reassembled->bytes.size() : 0);
        if (model_->packets.size() + retained.size() < 20000 &&
            retainedBytes_ + packetBytes <= 64 * 1024 * 1024) {
            retainedBytes_ += packetBytes;
            retained.push_back(std::move(p));
        } else
            displayDiscarded_++;
    }
    model_->append(std::move(retained));
    // 重组后的 HTTP 起始行可以把更早的数据段重新标记为 HTTP。
    bool changed = false;
    for (auto& p : model_->packets) {
        auto f = flows_.get(p.flowId);
        changed = flows_.syncProcessOwners(p) || changed;
        if (f && f->application == "HTTP" && p.payloadLength && p.protocol == "TCP") {
            p.protocol = "HTTP";
            protocolCounts_["TCP"]--;
            protocolCounts_["HTTP"]++;
            changed = true;
        }
    }
    if (changed && model_->rowCount()) {
        model_->dataChanged(model_->index(0, 0), model_->index(model_->rowCount() - 1, 8));
        proxy_->apply();
    }
    if (!batch.empty())
        updateSummary();
}
bool MainWindow::loadPcap(const QString& path) {
    stopCapture();
    std::vector<Packet> packets;
    try {
        // 先完整读取，确认成功后再丢弃当前会话。
        size_t loadedBytes = 0;
        auto fileInfo = readPcap(
            pathBytes(path),
            [&](Packet&& p) {
                if (loadedBytes + p.bytes.size() > 64 * 1024 * 1024)
                    return false;
                loadedBytes += p.bytes.size();
                packets.push_back(std::move(p));
                return packets.size() < 20000;
            },
            20000);
        resetSession();
        offline_ = true;
        append(std::move(packets));
        ipFragments_.finish();
        mode_->setText(fileInfo.pcapng ? "离线 PCAPNG 分析" : "离线 PCAP 分析");
        hint_->setText("已打开 " + QFileInfo(path).fileName() +
                       " · 离线文件不含进程归属；最多加载前 20000 条。");
        if (fileInfo.pcapng) hint_->setText(hint_->text() + QString(" 接口 %1；节 %2；跳过附加块 %3。")
            .arg(fileInfo.interfaces).arg(fileInfo.sections).arg(fileInfo.skippedBlocks));
        navigation_->setCurrentIndex(0);
        if (proxy_->rowCount())
            packets_->selectRow(0);
        else
            clearPacketDetails();
        refreshFlows();
        refreshProcesses();
        refreshStatistics();
        return true;
    } catch (const std::exception& e) {
        showError(qs(e.what()));
        return false;
    }
}
void MainWindow::updateSummary() {
    counters_[0]->setText(number(totalPackets_));
    counters_[1]->setText(number(flows_.all().size()));
    counters_[2]->setText(number(protocolCounts_["HTTP"]) + " / " + number(protocolCounts_["DNS"]));
    auto s = capture_.stats();
    counters_[3]->setText(offline_ ? "—" : number(s.queueDropped + s.driverDropped));
    footer_->setText(QString("显示 %1 / %2 条  ·  总量 %3  ·  异常 %4  ·  重组缓存 %5  ·  明细超限 %6")
                         .arg(proxy_->rowCount())
                         .arg(totalPackets_)
                         .arg(sizeText(totalBytes_))
                         .arg(warningPackets_)
                         .arg(sizeText(flows_.buffered()))
                         .arg(displayDiscarded_));
}
void MainWindow::applyFilter() {
    std::string error;
    if (proxy_->filter.compile(displayFilter_->text().toStdString(), error)) {
        displayFilter_->setStyleSheet("");
        proxy_->apply();
        hint_->setText("显示过滤器已应用 · 捕获过滤器使用不同的 BPF 语法。");
        if (proxy_->rowCount())
            packets_->selectRow(0);
        else
            clearPacketDetails();
    } else {
        displayFilter_->setStyleSheet("border:1px solid #dc7c70;background:#fff5f3;");
        hint_->setText("过滤器错误：" + qs(error) + "；保留上一次有效条件。");
    }
    updateSummary();
}
void MainWindow::selectPacket() {
    auto index = packets_->currentIndex();
    if (!index.isValid()) {
        clearPacketDetails();
        return;
    }
    int row = proxy_->mapToSource(index).row();
    if (row < 0 || size_t(row) >= model_->packets.size()) {
        clearPacketDetails();
        return;
    }
    const auto& frame = model_->packets[size_t(row)];
    {
        const QSignalBlocker block(byteView_);
        if (!frame.reassembled) byteView_->setCurrentIndex(0);
        byteView_->setEnabled(bool(frame.reassembled));
    }
    const auto& p = frame.reassembled && byteView_->currentIndex() == 1 ? *frame.reassembled : frame;
    fields_->clear();
    QTreeWidgetItem* parent = nullptr;
    for (const auto& f : p.fields) {
        auto* item = new QTreeWidgetItem(QStringList{qs(f.name), qs(f.value)});
        item->setData(0, Qt::UserRole, qulonglong(f.offset));
        item->setData(0, Qt::UserRole + 1, qulonglong(f.length));
        if (f.name.find("checksum") != std::string::npos) {
            auto color = f.value.find("incorrect") != std::string::npos ? "#af3c33" :
                f.value.find("verified") != std::string::npos ? "#176e4a" : "#6c7d8c";
            item->setForeground(1, QColor(color));
        }
        if (f.depth == 0) {
            fields_->addTopLevelItem(item);
            parent = item;
            item->setForeground(0, QColor("#087f8c"));
        } else if (parent)
            parent->addChild(item);
        else
            fields_->addTopLevelItem(item);
    }
    for (const auto& w : frame.warnings) {
        auto* item = new QTreeWidgetItem(QStringList{"⚠ 分析提示", qs(w)});
        fields_->addTopLevelItem(item);
        item->setForeground(0, QColor("#b45309"));
    }
    fields_->expandAll();
    QString text;
    hexPositions_.clear();
    const size_t limit = std::min(size_t(65535), p.bytes.size());
    constexpr size_t rowBytes = 8;
    for (size_t off = 0; off < limit; off += rowBytes) {
        text += QString("%1  ").arg(qulonglong(off), 6, 16, QChar('0'));
        for (size_t j = 0; j < rowBytes; j++) {
            if (off + j < limit) {
                hexPositions_.append(text.size());
                text += QString("%1 ").arg(p.bytes[off + j], 2, 16, QChar('0'));
            } else
                text += "   ";
            if (j == rowBytes / 2 - 1)
                text += ' ';
        }
        text += " ";
        for (size_t j = 0; j < rowBytes && off + j < limit; j++) {
            auto c = p.bytes[off + j];
            text += QChar(c >= 32 && c <= 126 ? c : '.');
        }
        text += '\n';
    }
    hex_->setPlainText(text);
    detailTitle_->setText(QString("#%1  ·  %2  ·  %3 → %4  ·  选择字段可高亮对应字节")
                              .arg(p.id)
                              .arg(qs(p.protocol))
                              .arg(qs(p.source))
                              .arg(qs(p.destination)));
    if (frame.reassembled) detailTitle_->setText(detailTitle_->text() +
        (byteView_->currentIndex() == 1 ? "  | 重组数据报；保存仍使用原始分片" : "  | 原始分片；可切换至重组数据报"));
}
void MainWindow::followSelected() {
    auto i = packets_->currentIndex();
    if (!i.isValid())
        return;
    auto& p = model_->packets[size_t(proxy_->mapToSource(i).row())];
    if (!p.flowId) {
        showError("所选报文不属于可追踪的 TCP 流。");
        return;
    }
    showFlow(p.flowId);
}
void MainWindow::showFlow(uint64_t id) {
    auto flow = flows_.get(id);
    if (!flow) {
        showError("该流已被缓存淘汰，请重新加载 PCAP 或重新抓包。");
        return;
    }
    auto* dialog = new QDialog(this);
    if (qApp->property("scriptedDemo").toBool() || qApp->property("headlessValidation").toBool())
        dialog->setAttribute(Qt::WA_DontShowOnScreen, true);
    dialog->setAttribute(Qt::WA_DeleteOnClose);
    dialog->setWindowTitle(QString("TCP 流 #%1 · %2").arg(id).arg(qs(flow->application)));
    dialog->resize(1060, 740);
    auto* v = new QVBoxLayout(dialog);
    v->addWidget(
        label(qs(endpoint(flow->a, flow->portA)) + "  ⇄  " + qs(endpoint(flow->b, flow->portB)), "title"));
    size_t retrans = 0, gaps = 0, conflicts = 0;
    for (const auto& d : flow->directions) {
        retrans += d.retransmitted;
        gaps += d.gaps();
        conflicts += d.conflicts;
    }
    v->addWidget(
        label(QString("包数 %1  ·  总字节 %2  ·  重传 %3 字节  ·  缺口 %4  ·  重叠冲突 %5  ·  PID %6")
                  .arg(flow->packets)
                  .arg(flow->bytes)
                  .arg(retrans)
                  .arg(gaps)
                  .arg(conflicts)
                  .arg(flow->pid),
              "subtitle"));
    auto* tabs = new QTabWidget;
    auto* dataPage = new QWidget;
    auto* dl = new QHBoxLayout(dataPage);
    for (int i = 0; i < 2; i++) {
        auto* panel = new QWidget;
        auto* pv = new QVBoxLayout(panel);
        pv->addWidget(label(i == 0 ? "端点 A → 端点 B" : "端点 B → 端点 A"));
        auto* edit = new QPlainTextEdit(qs(flow->directions[i].text()));
        edit->setReadOnly(true);
        edit->setFont(QFont("Consolas", 11));
        edit->setStyleSheet(i == 0 ? "color:#087f8c;background:#f0faf8;"
                                   : "color:#7954bc;background:#f6f3fc;");
        pv->addWidget(edit);
        dl->addWidget(panel);
    }
    tabs->addTab(dataPage, "重组内容");
    auto* analysis = new QPlainTextEdit(qs(flow->httpAnalysis().empty()
                                               ? "No complete HTTP/1.x message is available in the "
                                                 "contiguous stream. TLS content remains encrypted."
                                               : flow->httpAnalysis()));
    analysis->setReadOnly(true);
    analysis->setFont(QFont("Consolas", 11));
    tabs->addTab(analysis, "应用层消息");
    auto* scroll = new QScrollArea;
    scroll->setWidgetResizable(true);
    scroll->setWidget(new Timeline(flow));
    tabs->addTab(scroll, "通信时序");
    v->addWidget(tabs, 1);
    auto* buttons = new QHBoxLayout;
    auto* exportButton = button("导出重组文本");
    buttons->addWidget(exportButton);
    buttons->addStretch();
    auto* close = button("关闭", "primary");
    buttons->addWidget(close);
    v->addLayout(buttons);
    connect(close, &QPushButton::clicked, dialog, &QDialog::close);
    connect(exportButton, &QPushButton::clicked, dialog, [this, dialog, flow] {
        auto path = QFileDialog::getSaveFileName(dialog, "导出 TCP 流",
                                                 QString("stream-%1.txt").arg(flow->id), "Text (*.txt)");
        if (path.isEmpty())
            return;
        QFile f(path);
        if (f.open(QIODevice::WriteOnly)) {
            f.write(("A -> B\n" + flow->directions[0].text() + "\n\nB -> A\n" + flow->directions[1].text())
                        .c_str());
        } else
            showError(f.errorString());
    });
    dialog->show();
}
void MainWindow::refreshFlows() {
    int selected = -1;
    if (conversations_->currentRow() >= 0 && conversations_->item(conversations_->currentRow(), 0))
        selected = conversations_->item(conversations_->currentRow(), 0)->text().toInt();
    conversations_->setRowCount(int(flows_.all().size()));
    int r = 0;
    for (const auto& entry : flows_.all()) {
        const auto& f = *entry.second;
        cell(conversations_, r, 0, QString::number(f.id));
        cell(conversations_, r, 1, qs(endpoint(f.a, f.portA)));
        cell(conversations_, r, 2, qs(endpoint(f.b, f.portB)));
        cell(conversations_, r, 3, qs(f.application));
        cell(conversations_, r, 4, number(f.packets));
        cell(conversations_, r, 5, sizeText(f.bytes));
        cell(conversations_, r, 6, f.closed ? "已关闭" : "活动 / 未完整捕获");
        cell(conversations_, r, 7, f.pid ? QString::number(f.pid) : "未知");
        cell(conversations_, r, 8,
             QString("%1 B / %2")
                 .arg(f.directions[0].retransmitted + f.directions[1].retransmitted)
                 .arg(f.directions[0].gaps() + f.directions[1].gaps()));
        if (int(f.id) == selected)
            conversations_->selectRow(r);
        r++;
    }
}
void MainWindow::refreshProcesses() {
    struct Stats {
        std::string name;
        uint64_t flows = 0, packets = 0, bytes = 0;
        std::set<std::string> peers;
    };
    std::map<uint32_t, Stats> groups;
    for (const auto& entry : flows_.all()) {
        const auto& f = *entry.second;
        auto owners = f.owners;
        if (owners.empty())
            owners[0] = "未知 / 离线文件";
        for (const auto& owner : owners) {
            auto& g = groups[owner.first];
            g.name = owner.second;
            g.flows++;
            g.packets += f.packets;
            g.bytes += f.bytes;
            g.peers.insert(endpoint(f.a, f.portA) + " ↔ " + endpoint(f.b, f.portB));
        }
    }
    processes_->setRowCount(int(groups.size()));
    int r = 0;
    for (const auto& entry : groups) {
        cell(processes_, r, 0, entry.first ? QString::number(entry.first) : "未知");
        cell(processes_, r, 1, qs(entry.second.name));
        cell(processes_, r, 2, number(entry.second.flows));
        cell(processes_, r, 3, number(entry.second.packets));
        cell(processes_, r, 4, sizeText(entry.second.bytes));
        QString peers;
        for (const auto& p : entry.second.peers) {
            if (!peers.isEmpty())
                peers += "; ";
            peers += qs(p);
        }
        cell(processes_, r, 5, peers);
        r++;
    }
}
void MainWindow::refreshStatistics() {
    protocols_->setRowCount(int(protocolCounts_.size()));
    int r = 0;
    for (const auto& entry : protocolCounts_) {
        double share = totalPackets_ ? 100.0 * entry.second / totalPackets_ : 0;
        cell(protocols_, r, 0, qs(entry.first));
        cell(protocols_, r, 1, number(entry.second));
        cell(protocols_, r, 2, QString::number(share, 'f', 1) + " %");
        auto* progress = new QProgressBar;
        progress->setRange(0, 1000);
        progress->setValue(int(share * 10));
        progress->setTextVisible(false);
        progress->setStyleSheet("QProgressBar{border:0;background:#edf2f7;max-height:10px;margin:9px;}"
                                "QProgressBar::chunk{background:" +
                                protocolColor(entry.first).name() + ";}");
        protocols_->setCellWidget(r, 3, progress);
        r++;
    }
    auto s = capture_.stats();
    diagnostics_->setPlainText(
        QString("资源与诊断\n\n模式：%1\n解析数据包：%2\n原始总字节：%3\n含提示报文：%"
                "4\n明细上限：20000；因明细上限未保留：%5\n当前 TCP 流：%6 / 512；淘汰：%7\nTCP 重组缓存：%8 "
                "/ 32 MiB；每方向最多 128 "
                "KiB\n系统连接表条目：%9\n\n应用队列丢包：%10\n驱动缓冲丢包：%"
                "11\n\n统计说明：离线分析无法反推原始抓包时的丢包数量。驱动统计与应用队列统计分别计数，0 "
                "不能证明网络链路无丢包。进程归属每 500 ms "
                "刷新，短连接和受限进程可能无法匹配。\n\n支持范围：Ethernet / VLAN / loopback / raw IP / "
                "Linux cooked；IPv4 / IPv6 / TCP / UDP / ICMP / ARP / HTTP 1.x / DNS / TLS "
                "记录头。\n边界：IP 重组有资源和 TTL 上限，冲突分片丢弃；不解密 TLS、不解码 HTTP/2 或 QUIC。校验和卸载不确定时显示未验证。")
            .arg(offline_ ? "离线 PCAP" : "实时捕获")
            .arg(totalPackets_)
            .arg(totalBytes_)
            .arg(warningPackets_)
            .arg(displayDiscarded_)
            .arg(flows_.all().size())
            .arg(flows_.evicted)
            .arg(sizeText(flows_.buffered()))
            .arg(resolver_.count())
            .arg(s.queueDropped)
            .arg(offline_                 ? "离线不可用"
                 : s.driverStatsAvailable ? number(s.driverDropped)
                                          : "暂不可用"));
    const auto& fragments = ipFragments_.stats();
    diagnostics_->appendPlainText(QString("\nIP 分片：%1；完成数据报：%2；等待：%3；超时：%4；文件结束未完整：%5；"
        "重叠丢弃：%6；超限：%7；缓存：%8 / 8 MiB")
        .arg(fragments.fragments).arg(fragments.completed).arg(ipFragments_.pending()).arg(fragments.expired)
        .arg(fragments.incomplete).arg(fragments.overlaps).arg(fragments.limited).arg(sizeText(ipFragments_.buffered())));
}
void MainWindow::selectPage(int i) {
    pages_->setCurrentIndex(i);
    if (i == 1)
        refreshFlows();
    if (i == 2)
        refreshProcesses();
    if (i == 3)
        refreshStatistics();
}
void MainWindow::savePcap() {
    if (model_->packets.empty())
        return;
    auto path = exportPath(this, "保存已保留的全部报文", "capture.pcap", "PCAP (*.pcap)");
    if (path.isEmpty())
        return;
    try {
        writePcap(pathBytes(path), model_->packets, model_->packets.front().linkType);
        hint_->setText("已保存全部保留报文（不受显示过滤影响）：" + path);
    } catch (const std::exception& e) {
        showError(qs(e.what()));
    }
}
void MainWindow::exportJson() {
    if (model_->packets.empty())
        return;
    auto path = exportPath(this, "导出当前显示结果", "analysis.json", "JSON (*.json)");
    if (path.isEmpty())
        return;
    QFile out(path);
    if (!out.open(QIODevice::WriteOnly)) {
        showError(out.errorString());
        return;
    }
    out.write("[\n");
    for (int i = 0; i < proxy_->rowCount(); i++) {
        if (i)
            out.write(",\n");
        auto& p = model_->packets[size_t(proxy_->mapToSource(proxy_->index(i, 0)).row())];
        out.write(QByteArray::fromStdString(packetJson(p)));
    }
    out.write("\n]\n");
    if (out.error() != QFile::NoError)
        showError(out.errorString());
    else
        hint_->setText("已导出当前显示结果：" + path);
}
void MainWindow::exportCsv() {
    if (model_->packets.empty())
        return;
    auto path = exportPath(this, "导出当前显示结果", "analysis.csv", "CSV (*.csv)");
    if (path.isEmpty())
        return;
    QFile out(path);
    if (!out.open(QIODevice::WriteOnly)) {
        showError(out.errorString());
        return;
    }
    out.write("\xEF\xBB\xBF");
    QTextStream stream(&out);
#if QT_VERSION < QT_VERSION_CHECK(6, 0, 0)
    stream.setCodec("UTF-8");
#endif
    stream << "ID,Source,Destination,Protocol,Length,PID,Flow,Info,FlowPIDs\n";
    auto quote = [](QString s) {
        s.replace("\"", "\"\"");
        if (!s.isEmpty() && QString("=+-@").contains(s.at(0)))
            s.prepend('\'');
        return '"' + s + '"';
    };
    for (int i = 0; i < proxy_->rowCount(); i++) {
        const auto& p = model_->packets[size_t(proxy_->mapToSource(proxy_->index(i, 0)).row())];
        QStringList ownerPids;
        for (const auto& owner : p.flowProcesses) ownerPids << QString::number(owner.first);
        stream << p.id << ',' << quote(qs(p.source)) << ',' << quote(qs(p.destination)) << ','
               << quote(qs(p.protocol)) << ',' << p.originalLength << ',' << p.pid << ',' << p.flowId << ','
               << quote(qs(p.info)) << ',' << quote(ownerPids.join(";")) << '\n';
    }
    stream.flush();
    if (out.error() != QFile::NoError)
        showError(out.errorString());
    else
        hint_->setText("已导出当前显示结果：" + path);
}

void MainWindow::previewAndVerify(const QString& directory, const QString& fixture) {
    QJsonObject checks;
    QJsonObject fixes;
    auto check = [&](const char* name, bool passed) {
        checks[QString::fromUtf8(name)] = passed;
        if (!passed) throw std::runtime_error(std::string("UI validation failed: ") + name);
    };
    auto snapshot = [&](const QString& name) {
        qApp->processEvents();
        QPixmap image(size()); image.fill(Qt::transparent);
        render(&image); // 只渲染当前控件，不读取桌面画面。
        check(qPrintable(name), image.save(QDir(directory).filePath(name)));
    };
    auto destination = [&](const QString& name) { qApp->setProperty("validationExportPath", QDir(directory).filePath(name)); };
    auto checkFix = [&](const char* name, bool passed) {
        fixes[QString::fromUtf8(name)] = passed;
        if (!passed) throw std::runtime_error(std::string("Bugfix validation failed: ") + name);
    };
    auto fixSnapshot = [&](const QString& name) {
        qApp->processEvents();
        QPixmap image(size()); image.fill(Qt::transparent); render(&image);
        checkFix(qPrintable(name), image.save(QDir(directory).filePath(name)));
    };
    int code = 0;
    try {
        check("output_directory", QDir().mkpath(directory));
        QImage fontProbe(300, 50, QImage::Format_ARGB32_Premultiplied); fontProbe.fill(Qt::white);
        { QPainter painter(&fontProbe); painter.setPen(Qt::black); painter.drawText(5, 30, "FlowLens 网络协议"); }
        size_t ink = 0;
        for (int y = 0; y < fontProbe.height(); ++y)
            for (int x = 0; x < fontProbe.width(); ++x) ink += fontProbe.pixel(x, y) != qRgb(255, 255, 255);
        check("fonts_render_visible_text", ink > 50);
        check("no_capture_started", !capture_.running());
        check("offline_sample_load", loadPcap(fixture) && model_->rowCount() == 22);
        check("three_resizable_columns", packetSplit_->orientation() == Qt::Horizontal && packetSplit_->count() == 3);
        check("all_feature_tabs", navigation_->count() == 5);
        packets_->selectRow(0); selectPacket();
        snapshot("overview.png");
        auto checksum = fields_->findItems("IPv4 checksum", Qt::MatchExactly | Qt::MatchRecursive, 0);
        check("checksum_field_present", !checksum.empty() && checksum.front()->text(1).contains("verified"));
        fields_->setCurrentItem(checksum.front());
        check("field_byte_highlight", !hex_->extraSelections().empty());
        displayFilter_->setText("dns"); applyFilter();
        check("dns_filter", proxy_->rowCount() == 2);
        displayFilter_->setText("tcp and ("); applyFilter();
        check("invalid_filter_preserves_previous", proxy_->rowCount() == 2 && hint_->text().contains("错误"));
        destination("filtered.json"); exportJson();
        QFile json(QDir(directory).filePath("filtered.json")); check("json_export_open", json.open(QIODevice::ReadOnly));
        check("json_export_obeys_filter", QJsonDocument::fromJson(json.readAll()).array().size() == 2); json.close();
        destination("filtered.csv"); exportCsv();
        QFile csv(QDir(directory).filePath("filtered.csv")); check("csv_export_open", csv.open(QIODevice::ReadOnly));
        check("csv_export_obeys_filter", csv.readAll().trimmed().split('\n').size() == 3); csv.close();
        destination("all-original.pcap"); savePcap();
        check("pcap_save_ignores_display_filter", readPcap(pathBytes(QDir(directory).filePath("all-original.pcap")),
            [](Packet&&) { return true; }).packets == 22);
        displayFilter_->clear(); applyFilter();
        navigation_->setCurrentIndex(1); refreshFlows(); check("tcp_conversations", conversations_->rowCount() == 4);
        showFlow(1);
        auto dialogs = findChildren<QDialog*>();
        check("flow_dialog_preserves_analysis_and_timeline", !dialogs.empty() && dialogs.back()->findChild<QTabWidget*>()->count() == 3);
        for (auto* dialog : dialogs) dialog->close();
        navigation_->setCurrentIndex(2); check("process_tab", pages_->currentIndex() == 2);
        navigation_->setCurrentIndex(3); refreshStatistics(); check("protocol_statistics", protocols_->rowCount() >= 7);
        navigation_->setCurrentIndex(4); check("help_tab", pages_->currentIndex() == 4);
        navigation_->setCurrentIndex(0);
        auto* strict = findChild<QAction*>("checksumMode1"); check("checksum_mode_menu", strict != nullptr);
        strict->trigger(); check("strict_mode_selection", checksumMode_ == ChecksumMode::Strict);
        check("strict_mode_reload", loadPcap(fixture) && model_->packets[0].transportChecksum.state == ChecksumState::Verified);
        auto* automatic = findChild<QAction*>("checksumMode0"); automatic->trigger();
        auto sampleDirectory = QFileInfo(fixture).dir();
        check("pcapng_ui_load", loadPcap(sampleDirectory.filePath("plus/pcapng_cases/showcase_big.pcapng")) && model_->rowCount() == 22);
        check("pcapng_mode_visible", mode_->text().contains("PCAPNG"));
        check("transactional_invalid_load", !loadPcap(sampleDirectory.filePath("truncated_record.pcap")) && model_->rowCount() == 22);
        check("fragment_capture_load", loadPcap(sampleDirectory.filePath("plus/fragments_out_of_order.pcap")));
        int reconstructed = -1;
        for (size_t i = 0; i < model_->packets.size(); ++i)
            if (model_->packets[i].reassembled && model_->packets[i].ipVersion == 6) reconstructed = int(i);
        check("reconstructed_packet_available", reconstructed >= 0);
        packets_->selectRow(reconstructed); selectPacket();
        check("original_bytes_default", byteView_->isEnabled() && byteView_->currentIndex() == 0);
        byteView_->setCurrentIndex(1); selectPacket();
        const auto& reconstructedBytes = model_->packets[size_t(reconstructed)].reassembled->bytes;
        bool sameBytes = size_t(hexPositions_.size()) == reconstructedBytes.size();
        const auto rendered = hex_->toPlainText();
        for (size_t i = 0; sameBytes && i < reconstructedBytes.size(); ++i)
            sameBytes = rendered.mid(hexPositions_[int(i)], 2).toUInt(nullptr, 16) == reconstructedBytes[i];
        check("reassembled_fields_and_bytes", !fields_->findItems("TCP checksum", Qt::MatchExactly | Qt::MatchRecursive, 0).empty() && sameBytes);
        snapshot("ip-reassembly.png");
        check("simple_packet_ui_load", loadPcap(sampleDirectory.filePath("plus/pcapng_cases/simple_packet.pcapng")));
        check("missing_timestamp_display", model_->data(model_->index(0, 1)).toString() == "未提供");
        check("final_sample_load", loadPcap(fixture));
        packets_->selectRow(0); selectPacket();
        checksum = fields_->findItems("TCP checksum", Qt::MatchExactly | Qt::MatchRecursive, 0);
        if (!checksum.empty()) fields_->setCurrentItem(checksum.front());
        snapshot("overview.png");
        check("capture_still_stopped", !capture_.running());
        auto synFixture = model_->packets.at(0);
        auto ackFixture = model_->packets.at(2);
        checkFix("fragment_view_setup", loadPcap(sampleDirectory.filePath("plus/fragments_out_of_order.pcap")));
        for (size_t i = 0; i < model_->packets.size(); ++i) {
            if (model_->packets[i].reassembled) {
                packets_->selectRow(int(i)); selectPacket(); byteView_->setCurrentIndex(1); break;
            }
        }
        checkFix("reassembled_view_selected_before_reset", byteView_->isEnabled() && byteView_->currentIndex() == 1);
        resetSession();
        checkFix("reset_clears_packet_title", detailTitle_->text() == "选择数据包查看协议字段与原始字节");
        checkFix("reset_clears_fields_bytes_and_highlights", fields_->topLevelItemCount() == 0 &&
            hex_->toPlainText().isEmpty() && hexPositions_.isEmpty() && hex_->extraSelections().isEmpty());
        checkFix("reset_restores_original_byte_view", !byteView_->isEnabled() && byteView_->currentIndex() == 0);
        checkFix("reset_clears_counters_and_footer", counters_[0]->text() == "0" && counters_[1]->text() == "0" &&
            counters_[2]->text() == "0 / 0" && footer_->text().contains("显示 0 / 0"));
        mode_->setText("回归验证：会话已清空");
        hint_->setText("重组视图切换后重置；标题、字段、原始字节与高亮均已清空。");
        fixSnapshot("bugfix-reset.png");
        std::vector<Packet> first; first.push_back(synFixture); append(std::move(first));
        displayFilter_->setText("pid == 111101"); applyFilter();
        checkFix("unmatched_filter_clears_details", proxy_->rowCount() == 0 && fields_->topLevelItemCount() == 0 &&
            hex_->toPlainText().isEmpty() && detailTitle_->text() == "选择数据包查看协议字段与原始字节");
        ackFixture.pid = 111101; ackFixture.process = "fixture-client.exe";
        ackFixture.peerPid = 111102; ackFixture.peerProcess = "fixture-server.exe";
        std::vector<Packet> observed; observed.push_back(ackFixture); append(std::move(observed));
        checkFix("late_owner_rechecks_active_pid_filter", proxy_->rowCount() == 2);
        checkFix("earlier_handshake_has_flow_association", model_->packets[0].flowProcesses.count(111101) == 1 &&
            model_->packets[0].flowProcesses.count(111102) == 1);
        checkFix("direct_packet_pid_remains_unknown", model_->packets[0].pid == 0 && model_->packets[0].peerPid == 0);
        checkFix("association_source_visible", model_->data(model_->index(0, 6)).toString().contains("会话关联") &&
            model_->data(model_->index(0, 6), Qt::ToolTipRole).toString().contains("不会改写原包 PID"));
        packets_->selectRow(0); selectPacket();
        hint_->setText("确定性测试：后续 ACK 确认两个会话进程，早到 SYN 同样命中 PID 过滤；原包 PID 保持 0。");
        fixSnapshot("bugfix-pid-flow.png");
        checkFix("fixture_restored_after_bugfix_tests", loadPcap(fixture) && model_->rowCount() == 22 && !capture_.running());
    } catch (const std::exception& error) {
        code = 2; checks["error"] = QString::fromUtf8(error.what());
    }
    qApp->setProperty("validationExportPath", QVariant());
    checks["bugfix_checks"] = fixes;
    checks["status"] = code ? "FAIL" : "PASS";
    QFile output(QDir(directory).filePath("ui-validation.json"));
    if (output.open(QIODevice::WriteOnly)) output.write(QJsonDocument(checks).toJson()); else code = 2;
    QTimer::singleShot(0, qApp, [code] { QCoreApplication::exit(code); });
}
void MainWindow::scriptedDemo(const QString& directory, const QString& fixture) {
    QDir().mkpath(directory);
    resize(1440, 940);
    demoCaption_->show();
    auto* timer = new QTimer(this);
    auto step = std::make_shared<int>(0);
    auto checks = std::make_shared<QJsonObject>();
    connect(timer, &QTimer::timeout, this, [this, timer, step, checks, directory, fixture] {
        int n = (*step)++;
        if (n == 0) {
            loadPcap(fixture);
            (*checks)["offline_packet_count"] = model_->rowCount() == 22;
            demoCaption_->setText("离线实验样例 · 22 个报文覆盖 IPv4 / IPv6、HTTP、DNS、TLS");
        }
        if (n == 4) {
            packets_->selectRow(11);
            fields_->scrollToBottom();
            demoCaption_->setText("DNS 分层解析 · 域名压缩指针与响应地址");
        }
        if (n == 6) {
            auto items = fields_->findItems("Answer", Qt::MatchExactly | Qt::MatchRecursive, 0);
            if (!items.empty())
                fields_->setCurrentItem(items.front());
            (*checks)["field_byte_highlight"] = !hex_->extraSelections().isEmpty();
        }
        if (n == 8) {
            displayFilter_->setText("http or dns");
            applyFilter();
            (*checks)["http_dns_filter"] = proxy_->rowCount() == 8;
            demoCaption_->setText("显示过滤 · 解析后的协议筛选与逻辑表达式");
        }
        if (n == 12) {
            displayFilter_->setText("tcp and port == 18080");
            applyFilter();
            (*checks)["nonstandard_port_filter"] = proxy_->rowCount() == 13;
            demoCaption_->setText("非标准端口 18080 · HTTP 识别依据报文结构");
        }
        if (n == 16) {
            displayFilter_->clear();
            applyFilter();
            navigation_->setCurrentIndex(1);
            (*checks)["offline_flow_count"] = conversations_->rowCount() == 4;
            demoCaption_->setText("TCP 双向会话 · 重传去重、乱序重组与连接生命周期");
        }
        if (n == 20) {
            showFlow(1);
            demoCaption_->setText("TCP 流 #1 · 请求与响应重组完成，重传 29 字节已去重");
        }
        if (n == 24) {
            for (auto* d : findChildren<QDialog*>()) {
                auto* tabs = d->findChild<QTabWidget*>();
                if (tabs)
                    tabs->setCurrentIndex(1);
            }
            demoCaption_->setText("应用层分析 · HTTP 消息头、Content-Length 与完整性");
        }
        if (n == 28) {
            for (auto* d : findChildren<QDialog*>()) {
                auto* tabs = d->findChild<QTabWidget*>();
                if (tabs)
                    tabs->setCurrentIndex(2);
            }
            demoCaption_->setText("通信时序 · SYN / ACK / 数据 / FIN 的双向过程");
        }
        if (n == 32) {
            for (auto* d : findChildren<QDialog*>())
                d->close();
            navigation_->setCurrentIndex(2);
            demoCaption_->setText("进程追踪 · 离线文件不含 PID，实时捕获时关联系统连接表");
        }
        if (n == 36) {
            navigation_->setCurrentIndex(3);
            demoCaption_->setText("统计与边界 · 协议分布、资源上限和统计口径");
        }
        if (n == 40) {
            loadPcap(QFileInfo(fixture).dir().filePath("edge_cases.pcap"));
            displayFilter_->setText("malformed");
            applyFilter();
            demoCaption_->setText("异常报文 · 截断、非法长度及 IP 分片提示");
        }
        if (n == 44) {
            loadPcap(fixture);
            navigation_->setCurrentIndex(4);
            demoCaption_->setText("设计说明 · 抓包层次、应用层识别与 HTTPS 的可见性边界");
        }
        QTimer::singleShot(100, this, [this, directory, n] {
            QWidget* target = this;
            for (auto* d : findChildren<QDialog*>())
                if (d->isVisible())
                    target = d;
            target->grab().save(QDir(directory).filePath(QString("frame-%1.png").arg(n, 3, 10, QChar('0'))));
        });
        if (n == 48) {
            int loop = -1;
            for (size_t i = 0; i < adapterList_.size(); i++)
                if (adapterList_[i].name.find("Loopback") != std::string::npos)
                    loop = int(i);
            if (loop >= 0) {
                navigation_->setCurrentIndex(0);
                adapters_->setCurrentIndex(loop);
                captureFilter_->setText("tcp port 18080");
                startCapture();
                auto* helper = new QProcess(this);
                helper->setStandardOutputFile(QDir(directory).filePath("live-helper.json"));
                helper->setStandardErrorFile(QDir(directory).filePath("live-helper-error.txt"));
                helper->start(
                    QDir(QCoreApplication::applicationDirPath()).filePath("flowlens_native_probe.exe"),
                    {QDir(directory).filePath("live-gui.pcap")});
            }
            demoCaption_->setText("真实本机抓包 · Npcap loopback 捕获两个独立客户端的 HTTP 通信");
        }
        if (n == 64) {
            stopCapture();
            refreshFlows();
            refreshProcesses();
            navigation_->setCurrentIndex(2);
            demoCaption_->setText("真实进程关联 · 两个客户端与服务端 PID 分别归属，回环两端均可追踪");
            QFile state(QDir(directory).filePath("gui-live-state.json"));
            if (state.open(QIODevice::WriteOnly)) {
                QJsonObject object;
                object["packets"] = int(totalPackets_);
                object["tcp_flows"] = int(flows_.all().size());
                object["process_groups"] = processes_->rowCount();
                object["http_packets"] = int(protocolCounts_["HTTP"]);
                object["queue_drops"] = int(capture_.stats().queueDropped);
                QJsonArray ownershipCounts;
                bool pidConsistent = true;
                for (int row = 0; row < processes_->rowCount(); ++row) {
                    auto* item = processes_->item(row, 0);
                    if (!item || item->text() == "未知") continue;
                    const auto pid = item->text().toUInt();
                    uint64_t expected = 0, matched = 0;
                    for (const auto& entry : flows_.all())
                        if (entry.second->owners.count(pid)) expected += entry.second->packets;
                    DisplayFilter filter;
                    std::string error;
                    const bool compiled = filter.compile("pid == " + std::to_string(pid), error);
                    for (const auto& p : model_->packets) matched += compiled && filter.matches(p);
                    pidConsistent &= expected > 0 && expected == matched;
                    QJsonObject count; count["pid"] = int(pid); count["flow_packets"] = int(expected);
                    count["matched_packets"] = int(matched); ownershipCounts.append(count);
                }
                object["pid_packet_counts"] = ownershipCounts;
                object["pid_flow_filter_consistent"] = pidConsistent;
                object["offline_checks"] = *checks;
                bool offlineChecks = true;
                for (auto it = checks->begin(); it != checks->end(); ++it)
                    offlineChecks &= it.value().toBool();
                object["passed"] = totalPackets_ > 0 && flows_.all().size() >= 2 &&
                                   processes_->rowCount() >= 3 && offlineChecks && pidConsistent;
                state.write(QJsonDocument(object).toJson());
            }
        }
        if (n == 69) {
            for (int row = 0; row < processes_->rowCount(); ++row) {
                if (processes_->item(row, 2)->text() != "1") continue;
                auto* item = processes_->item(row, 0);
                if (item && item->text() != "未知") {
                    displayFilter_->setText("pid == " + item->text());
                    applyFilter();
                    navigation_->setCurrentIndex(0);
                    QJsonObject result;
                    result["pid"] = item->text().toInt();
                    result["matched_packets"] = proxy_->rowCount();
                    result["flow_packets"] = int(QLocale().toULongLong(processes_->item(row, 3)->text()));
                    result["passed"] = result["matched_packets"].toInt() == result["flow_packets"].toInt();
                    QFile output(QDir(directory).filePath("gui-pid-filter.json"));
                    if (output.open(QIODevice::WriteOnly)) output.write(QJsonDocument(result).toJson());
                    break;
                }
            }
            demoCaption_->setText("按 PID 筛选已确认会话 · 包数与进程页一致，原包 PID 保留直接观察结果");
        }
        if (n == 74) {
            navigation_->setCurrentIndex(1);
            demoCaption_->setText("实时会话列表 · 连接生命周期、协议、重传和缺口统计");
        }
        if (n == 79) {
            navigation_->setCurrentIndex(3);
            demoCaption_->setText("实时统计 · 驱动丢包与应用队列丢包分别记录");
        }
        if (n >= 83) {
            timer->stop();
            QTimer::singleShot(500, qApp, &QApplication::quit);
        }
    });
    timer->start(1000);
}
} // namespace fl
