#include <winsock2.h>
#include "flowlens/main_window.hpp"
#include <QApplication>
#include <QDir>
#include <QFile>
#include <QProxyStyle>
#include <QTextStream>
#include <QStyleFactory>
#include <QTimer>

namespace {
class FlowLensStyle final : public QProxyStyle {
  public:
    FlowLensStyle() : QProxyStyle(QStringLiteral("Fusion")) {}

    int styleHint(StyleHint hint, const QStyleOption* option = nullptr,
                  const QWidget* widget = nullptr, QStyleHintReturn* returnData = nullptr) const override {
        // Use a list below the control instead of centering a menu on its selected item.
        if (hint == QStyle::SH_ComboBox_Popup)
            return 0;
        return QProxyStyle::styleHint(hint, option, widget, returnData);
    }
};
} // namespace

int main(int argc, char** argv) {
    WSADATA ws;
    WSAStartup(MAKEWORD(2, 2), &ws);
    QApplication::setAttribute(Qt::AA_EnableHighDpiScaling);
    QApplication::setAttribute(Qt::AA_UseHighDpiPixmaps);
    QApplication app(argc, argv);
    app.setApplicationName("FlowLens");
    app.setOrganizationName("FlowLens Lab");
    app.setStyle(new FlowLensStyle);
    app.setFont(QFont("Microsoft YaHei UI", 9));
    auto args = app.arguments();
    bool demo = args.size() >= 4 && args[1] == "--scripted-demo";
    bool preview = args.size() >= 4 && args[1] == "--preview-ui";
    app.setProperty("scriptedDemo", demo);
    app.setProperty("headlessValidation", preview);
    fl::MainWindow window;
    if (demo || preview)
        window.setAttribute(Qt::WA_DontShowOnScreen, true);
    window.show();
    if (preview)
        QTimer::singleShot(0, &window, [&] { window.previewAndVerify(args[2], args[3]); });
    else if (args.size() >= 4 && args[1] == "--scripted-demo")
        window.scriptedDemo(args[2], args[3]);
    else if (args.size() > 1)
        window.loadPcap(args[1]);
    int result = app.exec();
    WSACleanup();
    return result;
}
