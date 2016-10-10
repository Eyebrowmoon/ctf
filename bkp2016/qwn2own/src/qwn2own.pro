QT      +=  webkitwidgets network widgets
HEADERS =   bkpdb.h \
            mainwindow.h 

SOURCES =   bkpdb.cpp \
            main.cpp \
            mainwindow.cpp

QMAKE_CXX = g++

QMAKE_CC = gcc

QMAKE_CXXFLAGS += -fpie -O3 -ggdb

QMAKE_LFLAGS += -Wl,-z,relro,-z,now -pie

CONFIG += c++11
