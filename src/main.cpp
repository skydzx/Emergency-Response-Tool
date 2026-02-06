#include "MainWindow.h"
#include <QApplication>
#include <QDebug>
#include <QDir>
#include <QDateTime>

int main(int argc, char *argv[]) {
    QApplication app(argc, argv);

    // 设置应用程序信息
    QCoreApplication::setApplicationName("应急响应工具");
    QCoreApplication::setApplicationVersion("1.0.0");
    QCoreApplication::setOrganizationName("EmergencyResponse");
    QCoreApplication::setOrganizationDomain("emergency-response.local");

    // 设置样式
    app.setStyle("Fusion");

    // 创建主窗口
    MainWindow mainWindow;
    mainWindow.show();

    qDebug() << "Emergency Response Tool started at:" << QDateTime::currentDateTime().toString(Qt::ISODate);

    return app.exec();
}
