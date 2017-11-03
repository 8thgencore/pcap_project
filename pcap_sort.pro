#-------------------------------------------------
#
# Project created by QtCreator 2017-09-28T16:06:01
#
#-------------------------------------------------


QT       += core gui

greaterThan(QT_MAJOR_VERSION, 4): QT += widgets

TARGET = QPcap
TEMPLATE = app


SOURCES += main.cpp\
        mainwindow.cpp \
    packetclass.cpp

HEADERS  += mainwindow.h \
    packetclass.h

FORMS    += mainwindow.ui

INCLUDEPATH += "E:\..\WpdPack\Include"
LIBS += -L"E:\..\WpdPack\Lib" -lwpcap -lpacket

DEFINES += WPCAP HAVE_REMOTE
