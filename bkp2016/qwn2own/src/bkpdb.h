#ifndef BKPDB_H
#define BKPDB_H

#include <QNetworkRequest>
#include <QWebPluginFactory>
#include <QDebug>
#include <QException>

class BKPException : public QException
{
public:
    void raise() const { throw *this; }
    BKPException *clone() const { return new BKPException(*this); }
};

class BKPStore : public QObject {
    Q_OBJECT
public:
    BKPStore(QObject * parent = 0, const QString &name = 0, quint8 tp = 0, QVariant var = 0, qulonglong store_ping = 0);
	void StoreData(QVariant v);

	Q_INVOKABLE QVariant getall();
	Q_INVOKABLE QVariant get(int idx);
	Q_INVOKABLE int insert(unsigned int idx, QVariant var);
	Q_INVOKABLE int append(QVariant var);
	Q_INVOKABLE void remove(int idx);
	Q_INVOKABLE void cut(int beg, int end);
	Q_INVOKABLE int size();

private:
    quint8 type; // specifies which type to of vector
                  // to use
    QVector<QVariant> varvect;
    QVector<qulonglong> intvect;
    QVector<QString> strvect;
    qulonglong store_ping;
};

class BKPKeyedStore : public QObject {
    Q_OBJECT
public:
    BKPKeyedStore(QObject * parent = 0, const QString &name = 0, QVariant var = 0, qulonglong store_ping = 0);
	void StoreData(QVariant v);

	Q_INVOKABLE QVariant getall();
	Q_INVOKABLE QVariant get(const QString &k);
	Q_INVOKABLE int insert(QVariant var);
	Q_INVOKABLE int remove(const QString &k);
	Q_INVOKABLE int size();

private:
    QMap<QString, QVariant> hashtb;
    qulonglong store_ping;
};

class DBInstance : public QObject {
    Q_OBJECT
public:
    DBInstance(QObject * parent = 0, const QString &name = 0, const QString &passwd = 0);

    Q_INVOKABLE QObject * createStore(const QString &name, int tp, QVariant var, qulonglong store_ping);
    Q_INVOKABLE QObject * createKeyedStore(const QString &name, QVariant var, qulonglong store_ping);

    QString & getpasswd() {return dbpass;}
private:
    QString dbname;
    QString dbpass;
    QMap<QString, QObject*> storemap;
};

class BKPDataBase : public QObject {
    Q_OBJECT
public:
    Q_INVOKABLE QObject * create(const QString &name, const QString &password);
    Q_INVOKABLE QObject * getdb(const QString &name, const QString &password);
    Q_INVOKABLE int deldb(const QString &name, const QString &password);
private:
    QHash<QString, DBInstance*> dbhash_table;
};

#endif
