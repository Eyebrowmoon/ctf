#include <QtWidgets>
#include <QtNetwork>
#include <QtWebKitWidgets>
#include <iostream>
#include "bkpdb.h"
#include "mainwindow.h"

MainWindow::MainWindow(const QUrl& url)
{
    progress = 0;

    QWebSettings::globalSettings()->setAttribute(QWebSettings::PluginsEnabled, true);
    QNetworkProxyFactory::setUseSystemConfiguration(true);

    view = new QWebView(this);
    view->load(url);

    connect(view, SIGNAL(loadFinished(bool)), SLOT(adjustLocation()));
    connect(view, SIGNAL(titleChanged(QString)), SLOT(adjustTitle()));
    connect(view, SIGNAL(loadProgress(int)), SLOT(setProgress(int)));
    connect(view, SIGNAL(loadFinished(bool)), SLOT(finishLoading(bool)));
    connect(view, SIGNAL(urlChanged(QUrl)), SLOT(newurl()));

    locationEdit = new QLineEdit(this);
    locationEdit->setSizePolicy(QSizePolicy::Expanding, locationEdit->sizePolicy().verticalPolicy());
    connect(locationEdit, SIGNAL(returnPressed()), SLOT(changeLocation()));

    QToolBar *toolBar = addToolBar(tr("Navigation"));
    toolBar->addAction(view->pageAction(QWebPage::Back));
    toolBar->addAction(view->pageAction(QWebPage::Forward));
    toolBar->addAction(view->pageAction(QWebPage::Reload));
    toolBar->addAction(view->pageAction(QWebPage::Stop));
    toolBar->addWidget(locationEdit);

    setCentralWidget(view);
    setUnifiedTitleAndToolBarOnMac(true);
}

void MainWindow::viewSource()
{
    QNetworkAccessManager* accessManager = view->page()->networkAccessManager();
    QNetworkRequest request(view->url());
    QNetworkReply* reply = accessManager->get(request);
    connect(reply, SIGNAL(finished()), this, SLOT(slotSourceDownloaded()));
}

void MainWindow::slotSourceDownloaded()
{
    QNetworkReply* reply = qobject_cast<QNetworkReply*>(const_cast<QObject*>(sender()));
    QTextEdit* textEdit = new QTextEdit(NULL);
    textEdit->setAttribute(Qt::WA_DeleteOnClose);
    textEdit->show();
    textEdit->setPlainText(reply->readAll());
    reply->deleteLater();
}

void MainWindow::adjustLocation()
{
    locationEdit->setText(view->url().toString());
}

void MainWindow::changeLocation()
{
    QUrl url = QUrl::fromUserInput(locationEdit->text());
    view->load(url);
    view->setFocus();
}

void MainWindow::adjustTitle()
{
    if (progress <= 0 || progress >= 100)
        setWindowTitle(view->title());
    else
        setWindowTitle(QString("%1 (%2%)").arg(view->title()).arg(progress));
}

void MainWindow::setProgress(int p)
{
    progress = p;
    adjustTitle();
}

void MainWindow::finishLoading(bool)
{
    progress = 100;
    adjustTitle();
}

void MainWindow::newurl()
{
    view->page()->mainFrame()->addToJavaScriptWindowObject(QString("BKPDataBase"), new BKPDataBase);
}
