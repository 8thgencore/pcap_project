#ifndef PACKETCLASS_H
#define PACKETCLASS_H
#pragma once

#endif // PACKETCLASS_H

#include <QVector>
#include <fstream>

using namespace std;

class Packet
{
public: // инициализвция класса
    static int choose;

    Packet(); // конструктор
    Packet(const Packet &obj); // конструктор копирования

    struct pcap_pkthdr *mHeaders;
    uchar              *mDatas;
    struct sniff_ip    *mIp;
    const uchar        *mPayload;
    int                 mIndexes;

    // оперотор присваивание
    Packet operator = (Packet &obj);
    Packet operator = (const Packet &obj);

    // операторы сравнения
    friend bool operator < (Packet &obj1, Packet &obj2);
    friend bool operator < (const Packet &obj1, Packet &obj2);
    friend bool operator < (Packet &obj1, const Packet &obj2);
    friend bool operator < (const Packet &obj1, const Packet &obj2);

    // перегрузка ввода/вывода
    friend ostream &operator << (ostream &stream, Packet &obj);
    friend istream &operator >> (ostream &stream, Packet &obj);
};
