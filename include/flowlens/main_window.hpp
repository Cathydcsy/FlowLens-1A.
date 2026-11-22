#pragma once
#include "capture.hpp"
#include "filter.hpp"
#include "process.hpp"
#include "stream.hpp"
#include "ip_reassembly.hpp"
#include <QMainWindow>
#include <QAbstractTableModel>
#include <QSortFilterProxyModel>
#include <QVector>
#include <memory>

class QLabel;
class QLineEdit;
class QComboBox;
class QPushButton;
class QTableView;
class QTableWidget;
class QTreeWidget;
class QPlainTextEdit;
class QStackedWidget;
class QTabBar;
class QSplitter;
namespace fl {
class PacketModel : public QAbstractTableModel {
  public:
    std::vector<Packet> packets;
    uint64_t firstTimestamp = 0;
    bool hasTimestamp = false;
    explicit PacketModel(QObject* parent = nullptr) : QAbstractTableModel(parent) {}
    int rowCount(const QModelIndex& parent = QModelIndex()) const override;
    int columnCount(const QModelIndex& parent = QModelIndex()) const override;
    QVariant data(const QModelIndex& index, int role = Qt::DisplayRole) const override;
    QVariant headerData(int section, Qt::Orientation orientation, int role = Qt::DisplayRole) const override;
    void append(std::vector<Packet>&& batch);
    void reset();
};
class PacketProxy : public QSortFilterProxyModel {
  public:
    DisplayFilter filter;
    explicit PacketProxy(QObject* parent = nullptr) : QSortFilterProxyModel(parent) {}
    bool filterAcceptsRow(int row, const QModelIndex& parent) const override;
    void apply() {
        invalidateFilter();
    }
};
class MainWindow : public QMainWindow {
    Capture capture_;
    ProcessResolver resolver_;
    FlowTable flows_;
    IpReassembler ipFragments_;
    PacketModel* model_;
    PacketProxy* proxy_;
    QComboBox* adapters_;
    QLineEdit* captureFilter_;
    QLineEdit* displayFilter_;
    QPushButton* start_;
    QPushButton* stop_;
    QLabel* mode_;
    QLabel* hint_;
    QLabel* counters_[4]{};
    QTableView* packets_;
    QTreeWidget* fields_;
    QPlainTextEdit* hex_;
    QLabel* detailTitle_;
    QTableWidget* conversations_;
    QTableWidget* processes_;
    QTableWidget* protocols_;
    QPlainTextEdit* diagnostics_;
    QStackedWidget* pages_;
    QTabBar* navigation_;
    QSplitter* packetSplit_;
    QComboBox* byteView_;
    ChecksumMode checksumMode_ = ChecksumMode::Automatic;
    QLabel* footer_;
    QLabel* demoCaption_;
    std::vector<Adapter> adapterList_;
    QVector<int> hexPositions_;
    uint64_t totalPackets_ = 0, totalBytes_ = 0, firstNs_ = 0, warningPackets_ = 0, displayDiscarded_ = 0,
             retainedBytes_ = 0;
    bool offline_ = true, wasRunning_ = false;
    int tick_ = 0;
    std::map<std::string, uint64_t> protocolCounts_;
    void refreshAdapters();
    void startCapture();
    void stopCapture();
    void timerTick();
    void append(std::vector<Packet>&& packets);
    void resetSession();
    void clearPacketDetails();
    void updateSummary();
    void selectPacket();
    void applyFilter();
    void showFlow(uint64_t id);
    void refreshFlows();
    void refreshProcesses();
    void savePcap();
    void exportJson();
    void exportCsv();
    void showError(const QString& message);
    void selectPage(int index);
    void followSelected();
    void refreshStatistics();

  public:
    explicit MainWindow();
    ~MainWindow() override;
    bool loadPcap(const QString& path);
    void scriptedDemo(const QString& outputDirectory, const QString& fixture);
    void previewAndVerify(const QString& outputDirectory, const QString& fixture);
};
} // namespace fl
