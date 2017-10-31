#include "packetclass.h"
#include "mainwindow.h"
#include <QTextCodec> // подключение класса кодека текста
#include <QTextStream> // подключение класса потока текста

using namespace std;

Packet::Packet()
{};

Packet::Packet(const Packet &obj) // описание конструктора копирования
{
    mHeaders = obj.mHeaders;
    mDatas   = obj.mDatas;
    mIp      = obj.mIp;
    mIndexes = obj.mIndexes;
}

Packet Packet::operator = (Packet &obj) // описание оператора присваивания
{
    this->mHeaders = obj.mHeaders;
    this->mDatas   = obj.mDatas;
    this->mIp      = obj.mIp;
    this->mIndexes = obj.mIndexes;
    
    return *this;
}

Packet Packet::operator = (const Packet &obj) // описание оператора присваивания
{
    this->mHeaders = obj.mHeaders;
    this->mDatas   = obj.mDatas;
    this->mIp      = obj.mIp;
    this->mIndexes = obj.mIndexes;

    return *this;
}

ostream &operator << (ostream &stream, Packet &obj)
{
    stream.write((char* )&obj.mIndexes, sizeof(int));
    stream.write((char* )&obj.mHeaders, sizeof(long int));
    stream.write((char* )&obj.mDatas, sizeof(&obj.mHeaders));
    stream.write((char* )&obj.mIp, sizeof(long int));

// для IPv4
    stream.write((char* )&obj.IPv4_dataLen, sizeof(unsigned int));
}

istream &operator >> (istream &stream, Packet &obj)
{
    stream.read((char* )&obj.mIndexes, sizeof(int));
    stream.read((char* )&obj.mHeaders, sizeof(long int));
    stream.read((char* )&obj.mDatas, sizeof(&obj.mHeaders));
    stream.read((char* )&obj.mIp, sizeof(unsigned short));
    //    stream.read((char* )&obj.mIp->ip_len, sizeof(unsigned short));
    //    stream.read((char* )&obj.mIp->ip_ttl, sizeof(long int));
    //    stream.read((char* )&obj.mIp->ip_src.s_addr, sizeof(long int));
    //    stream.read((char* )&obj.mIp->ip_dst.s_addr, sizeof(long int));
    //    stream.read((char* )&obj.mIp->ip_vhl, sizeof(long int));
    //    stream.read((char* )&obj.mIp->ip_sum, sizeof(long int));
    //    stream.read((char* )&obj.mIp->ip_p, sizeof(long int));
    //    stream.read((char* )&obj.mIp->ip_tos, sizeof(long int));

    // для IPv4
        stream.read((char* )&obj.IPv4_dataLen, sizeof(unsigned int));
}

int Packet::choose;
