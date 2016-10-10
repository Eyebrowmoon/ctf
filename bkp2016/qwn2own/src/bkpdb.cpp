#include <QtGui>
#include <QtNetwork>
#include <QWebPluginFactory>
#include <stdlib.h>
#include "bkpdb.h"

template <typename T>
QVariantList toVariantList( const QList<T> &list )
{
    QVariantList newList;
    foreach( const T &item, list )
        newList << item;

    return newList;
}

int BKPStore::size(){
    if(this->type == 0){
        return this->varvect.size();
    }else if(this->type == 1){
        return this->intvect.size();
    }else if(this->type == 2){
        return this->strvect.size();
    }else{
        // this doesn't happen ever
        BKPException ex;
        throw ex;
    }
}

QVariant BKPStore::get(int idx){
    if(this->type == 0){
        return this->varvect.value(idx);
    }else if(this->type == 1){
        return this->intvect.value(idx);
    }else if(this->type == 2){
        return this->strvect.value(idx);
    }else{
        // this doesn't happen ever
        BKPException ex;
        throw ex;
    }
}

QVariant BKPStore::getall(){
    if(this->type == 0){
        return QVariant(this->varvect.toList());
    }else if(this->type == 1){
        return QVariant(toVariantList(this->intvect.toList()));
    }else if(this->type == 2){
        return QVariant(this->strvect.toList());
    }else{
        // this doesn't happen ever
        BKPException ex;
        throw ex;
    }
}

void BKPStore::remove(int idx){
    if(this->type == 0){
        this->varvect.erase(this->varvect.begin() + idx);
    }else if(this->type == 1){
        this->intvect.erase(this->intvect.begin() + idx);
    }else if(this->type == 2){
        this->strvect.erase(this->strvect.begin() + idx);
    }else{
        // this doesn't happen ever
        BKPException ex;
        throw ex;
    }
}

void BKPStore::cut(int beg, int end){
    if(this->type == 0){
        if(end > this->varvect.size()){
            BKPException ex;
            throw ex;
        }
        this->varvect.erase(this->varvect.begin() + beg, this->varvect.begin() + end);
    }else if(this->type == 1){
        if(end > this->intvect.size()){
            BKPException ex;
            throw ex;
        }
        this->intvect.erase(this->intvect.begin() + beg, this->intvect.begin() + end);
    }else if(this->type == 2){
        if(end > this->strvect.size()){
            BKPException ex;
            throw ex;
        }
        this->strvect.erase(this->strvect.begin() + beg, this->strvect.begin() + end);
    }else{
        // this doesn't happen ever
        BKPException ex;
        throw ex;
    }
}

int BKPStore::insert(unsigned int idx, QVariant var){
    if(this->type == 0){
        if((var.userType() != QMetaType::QString) && (var.userType() != QMetaType::Double)){
            return 0;
        }
        if(idx >= (unsigned int)this->varvect.size()){
            return 0; 
        }
        this->varvect[idx] = var;
    }else if(this->type == 1){
        bool ok;
        qulonglong tmp = var.toULongLong(&ok);
        if(!ok){
            return 0;
        }
        if(idx >= (unsigned int)this->intvect.size()){
            return 0; 
        }
        this->intvect[idx] = tmp;
    }else if(this->type == 2){
        QString tmp = var.toString();
        if(var == ""){
            return 0; 
        }
        if(idx >= (unsigned int)this->strvect.size()){
            return 0; 
        }
        this->strvect[idx] = tmp;
    }else{
        // this doesn't happen ever
        BKPException ex;
        throw ex;
    }
    return 1;
}

int BKPStore::append(QVariant var){
    if(this->type == 0){
        if((var.userType() != QMetaType::QString) && (var.userType() != QMetaType::Double)){
            return 0;
        }
        this->varvect.append(var);
    }else if(this->type == 1){
        bool ok;
        qulonglong tmp = var.toULongLong(&ok);
        if(!ok){
            return 0;
        }
        this->intvect.append(tmp);
    }else if(this->type == 2){
        QString tmp = var.toString();
        if(var == ""){
            return 0; 
        }
        this->strvect.append(tmp);
    }else{
        // this doesn't happen ever
        BKPException ex;
        throw ex;
    }
    return 1;
}

void BKPStore::StoreData(QVariant var){
    int idx;
    QList<QVariant> lst;

    if(var.userType() != QMetaType::QVariantList){
        BKPException ex;
        throw ex;
    }

    // this should not fail at this point
    lst = var.toList();

    if(this->type == 1){
        QVector<qulonglong> tmpls;
        for(idx = 0; idx < lst.size(); idx++){
            bool ok;
            qulonglong tmp = lst.at(idx).toULongLong(&ok);

            if(ok == true){
                tmpls.append(tmp);
            }else{
                BKPException ex;
                throw ex;
            }
        }
        this->intvect += tmpls;
    }else if(this->type == 2){
        QVector<QString> tmpls;
        for(idx = 0; idx < lst.size(); idx++){
            QString tmp = lst.at(idx).toString();

            if(tmp != ""){
                tmpls.append(tmp);
            }else{
                BKPException ex;
                throw ex;
            }
        }
        this->strvect += tmpls;
    }else if(this->type == 0){
        QVector<QVariant> tmpls;
        for(idx = 0; idx < lst.size(); idx++){
            QVariant tmp = lst.at(idx);

            if((tmp.userType() != QMetaType::QString) && (tmp.userType() != QMetaType::Double)){
                BKPException ex;
                throw ex;
            }

            tmpls.append(tmp);
        }
        this->varvect += tmpls;
    }else{
        // this will never happen
        BKPException ex;
        throw ex;
    }
}

BKPStore::BKPStore(QObject * parent, const QString &name, quint8 tp, QVariant var, qulonglong store_ping) : QObject(parent){
    if(tp > 2){
        BKPException ex;
        throw ex;
    }

    this->store_ping = store_ping;
    this->setObjectName(name);
    this->type = tp;

    this->StoreData(var);
}

QVariant BKPKeyedStore::get(const QString &k){
    QVariant ret = this->hashtb.value(k);
	return ret;
}

QVariant BKPKeyedStore::getall(){
	return this->hashtb;
}

int BKPKeyedStore::insert(QVariant var){
    try{
        this->StoreData(var);
    }catch(BKPException &e){
        return 0; 
    }
    return 1;
}

int BKPKeyedStore::size(){
    return this->hashtb.size();
}

int BKPKeyedStore::remove(const QString &k){
    return this->hashtb.remove(k);
}

void BKPKeyedStore::StoreData(QVariant var){
    QMap<QString, QVariant> tmpm;
    if(var.userType() != QMetaType::QVariantMap){
        BKPException ex;
        throw ex;
    }

    tmpm = var.toMap();

    if(tmpm.isEmpty()){
        BKPException ex;
        throw ex;
    }

    QMapIterator<QString, QVariant> it(tmpm);
    QMap<QString, QVariant> thash;

    while(it.hasNext()){
        it.next();
        if(it.value().userType() != QMetaType::QString && it.value().userType() != QMetaType::Double){
            BKPException ex;
            throw ex;
        }
        thash.insert(it.key(), it.value());
    }
    this->hashtb.unite(thash);
}

BKPKeyedStore::BKPKeyedStore(QObject * parent, const QString &name, QVariant var, qulonglong store_ping) : QObject(parent){
    this->setObjectName(name);
    this->store_ping = store_ping;

    this->StoreData(var);
}

QObject * BKPDataBase::create(const QString &name, const QString &passwd){
    DBInstance * db = new DBInstance(this, name, passwd);
    DBInstance * val = this->dbhash_table.value(name, NULL);

    if(val == NULL){
        this->dbhash_table.insert(name, db);
    }else{
        db = val; 
    }

    return db;
}

QObject * BKPDataBase::getdb(const QString &name, const QString &passwd){
    DBInstance * val = this->dbhash_table.value(name, NULL);
    if(val != NULL){
        if(val->getpasswd() == passwd){
            return val;
        }
    }
    return NULL;
}

int BKPDataBase::deldb(const QString &name, const QString &passwd){
    DBInstance * val = this->dbhash_table.value(name, NULL);
    int ret = 0;
    if(val != NULL){
        if(val->getpasswd() == passwd){
            ret = this->dbhash_table.remove(name);
            //delete val;
        }
    }
    return ret;
}

// Store a list of strings and/or ints
QObject * DBInstance::createStore(const QString &name, int tp, QVariant var, qulonglong store_ping){
    BKPStore * st = NULL;
    
    try{
        st = new BKPStore(this, name, tp, var, store_ping);
    }catch(BKPException &e){
        return NULL; 
    }

    this->storemap.insert(name, st);
    return st;
}

// Store a hashmap of strings and/or ints
QObject * DBInstance::createKeyedStore(const QString &name, QVariant var, qulonglong store_ping){
    BKPKeyedStore * st = NULL;

    try{
        st = new BKPKeyedStore(this, name, var, store_ping);
    }catch(BKPException &e){
        return NULL; 
    }

    this->storemap.insert(name, st);
    return st;
}

DBInstance::DBInstance(QObject * parent, const QString & name, const QString & passwd) : QObject(parent){
    this->setObjectName(name);
    this->dbname = name;
    this->dbpass = passwd;
}
