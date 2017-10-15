#include "mainwindow.h"
#include "ui_mainwindow.h"
#include "packetclass.h"
#include <algorithm>

using namespace std;

MainWindow::MainWindow(QWidget *parent) :
    QMainWindow(parent),
    ui(new Ui::MainWindow)
{
    ui->setupUi(this);

    connect(ui->pbOpen,SIGNAL(clicked()),SLOT(slotOpen()));
    connect(ui->pbStart,SIGNAL(clicked()),SLOT(slotCapture()));
    connect(ui->pbSort,SIGNAL(clicked()),SLOT(slotSort()));

    //mSize_ethernet = sizeof(struct sniff_ethernet);
    mSize_ip = sizeof(struct sniff_ip); // инициализируем размер структуры
    //mSize_tcp = sizeof(struct sniff_tcp);
}

// деструктор
MainWindow::~MainWindow()
{
    delete ui;
}

void MainWindow::slotOpen() // функция открытия файла
{
    file = QFileDialog::getOpenFileName(this, tr("Open File"), "C:", tr("DATA(*.pcap)"));
}

void MainWindow::slotCapture()
{
    mPacket.resize(n);//инициализируем n пакетов

    for (int i=0; i<n; i++) //очищаем память
    {

    }

    ui->te->clear();//очищаем экран

    char error[PCAP_ERRBUF_SIZE]; // массив ошибок

    pcap_t *handle = pcap_open_offline(file.toStdString().c_str(), error);

    ui->te->append("Список пакетов:");

    for (int i=0; i<n; i++) // перебираем пакеты
    {
        struct pcap_pkthdr *header; // структура заголовка
        const u_char *data; // массив храниение данных

        pcap_next_ex(handle,&header,&data);

        mPacket[i].mHeaders = new pcap_pkthdr;
        *mPacket[i].mHeaders =* header;
        mPacket[i].mDatas = new u_char[mPacket[i].mHeaders->len];
        for (unsigned j = 0; j < mPacket[i].mHeaders->len; j++)
            mPacket[i].mDatas[j] = data[j];
        mPacket[i].mIp = (struct sniff_ip*)(mPacket[i].mDatas);
        //mPacket[i].mEthernet.push_back((struct sniff_ethernet*)(mPacket[i].mDatas) + mSize_ip);
        //mPacket[i].mTcp.push_back((struct sniff_tcp*)(mPacket[i].mDatas + mSize_ethernet + mSize_ip));
        //mPacket[i].mPayload.push_back((u_char *)(mPacket[i].mDatas + mSize_ethernet + mSize_ip + mSize_tcp));
        mPacket[i].mIndexes = i+1;

        ui->te->append(QString("\n===== Пакет №%1 =====").arg(mPacket[i].mIndexes));
        ui->te->append(QString("Длина пакета: %1").arg(header->caplen));
        ui->te->append(QString("Получено: %1").arg(header->len));
        ui->te->append(QString("Метка времени: %1").arg(header->ts.tv_sec));
        ui->te->append(QString("Метка времени (микросек): %1").arg(header->ts.tv_usec));
    }

    pcap_close(handle);
}

void MainWindow::slotSort() // функция для сортировки пакетов
{
    ui->te->clear();
    if (ui->cbtype->currentText() == "Внутренняя") //внутренняя сортировка пакетов
    {
        if (ui->cb->currentText() == "По длине")
        {
            int h, i, j;
            for (h = n/2; h > 0; h = h/2)
                for(i = 0; i < n-h; i++)
                    for(j = i; j >= 0; j = j - h)
                        if(mPacket[j].mIp->ip_len > mPacket[j+h].mIp->ip_len)
                            Exchange(j, j+h);
                        else j = 0;
        }
        else if (ui->cb->currentText() == "По времени жизни")
        {
            int h, i, j;
            for (h = n/2; h > 0; h = h/2)
                for(i = 0; i < n-h; i++)
                    for(j = i; j >= 0; j = j - h)
                        if(mPacket[j].mIp->ip_ttl > mPacket[j+h].mIp->ip_ttl)
                            Exchange(j, j+h);
                        else j = 0;
        }
        else if (ui->cb->currentText() == "По адресу получателя")
        {
            int h, i, j;
            for (h = n/2; h > 0; h = h/2)
                for(i = 0; i < n-h; i++)
                    for(j = i; j >= 0; j = j - h)
                        if(mPacket[j].mIp->ip_dst.s_addr > mPacket[j+h].mIp->ip_dst.s_addr)
                            Exchange(j, j+h);
                        else j = 0;
        }
        else if (ui->cb->currentText() == "По адресу отправителя")
        {
            int h, i, j;
            for (h = n/2; h > 0; h = h/2)
                for(i = 0; i < n-h; i++)
                    for(j = i; j >= 0; j = j - h)
                        if(mPacket[j].mIp->ip_src.s_addr > mPacket[j+h].mIp->ip_src.s_addr)
                            Exchange(j, j+h);
                        else j = 0;
        }
        else if (ui->cb->currentText() == "По длине заголовочной части пакета")
        {
            int h, i, j;
            for (h = n/2; h > 0; h = h/2)
                for(i = 0; i < n-h; i++)
                    for(j = i; j >= 0; j = j - h)
                        if(mPacket[j].mIp->ip_vhl > mPacket[j+h].mIp->ip_vhl)
                            Exchange(j, j+h);
                        else j = 0;
        }
        else if (ui->cb->currentText() == "По контрольной сумме (первый байт контрольной суммы)")
        {
            int h, i, j;
            for (h = n/2; h > 0; h = h/2)
                for(i = 0; i < n-h; i++)
                    for(j = i; j >= 0; j = j - h)
                        if((mPacket[j].mIp->ip_sum & 0xFF00) > (mPacket[j+h].mIp->ip_sum & 0xFF00))
                            Exchange(j, j+h);
                        else j = 0;
        }
        else if (ui->cb->currentText() == "По контрольной сумме (последний байт контрольной суммы)")
        {
            int h, i, j;
            for (h = n/2; h > 0; h = h/2)
                for(i = 0; i < n-h; i++)
                    for(j = i; j >= 0; j = j - h)
                        if((mPacket[j].mIp->ip_sum & 0xFF) > (mPacket[j+h].mIp->ip_sum & 0xFF))
                            Exchange(j, j+h);
                        else j = 0;
        }
        else if (ui->cb->currentText() == "По типу инкапсулированного пакета(4 - TCP,  17 - UDP)")
        {
            int h, i, j;
            for (h = n/2; h > 0; h = h/2)
                for(i = 0; i < n-h; i++)
                    for(j = i; j >= 0; j = j - h)
                        if((mPacket[j].mIp->ip_p) > (mPacket[j+h].mIp->ip_p))
                            Exchange(j, j+h);
                        else j = 0;
        }

        for (int i=0; i<n; i++)
        {
            ui->te->append(QString("===== Пакет №%1 =====").arg(mPacket[i].mIndexes));
            ui->te->append(QString("Длина пакета: %1").arg(mPacket[i].mHeaders->caplen));
            ui->te->append(QString("Получено: %1").arg(mPacket[i].mHeaders->len));
            ui->te->append(QString("Метка времени: %1").arg(mPacket[i].mHeaders->ts.tv_sec));
            ui->te->append(QString("Метка времени (микросек): %1").arg(mPacket[i].mHeaders->ts.tv_usec));

            ui->te->append(QString("========= IP сортировка: ========="));
            ui->te->append(QString("Длина: %1").arg(mPacket[i].mIp->ip_len));
            ui->te->append(QString("Время жизни: %1").arg(mPacket[i].mIp->ip_ttl));
            ui->te->append(QString("Адрес получателя: %1").arg(mPacket[i].mIp->ip_dst.s_addr));
            ui->te->append(QString("Адрес отправителя: %1").arg(mPacket[i].mIp->ip_src.s_addr));
            ui->te->append(QString("Длина заголовочной части пакета: %1").arg(mPacket[i].mIp->ip_vhl));
            ui->te->append(QString("Контрольная сумма: %1").arg(mPacket[i].mIp->ip_sum));
            ui->te->append(QString("Протокола транспортного уровня: %1").arg(mPacket[i].mIp->ip_p)); // 6 - TCP, 17 - UDP
            ui->te->append(QString("Тип обслуживания: %1").arg(mPacket[i].mIp->ip_tos)); //0-2 приоритет данного IP-сегмент
            ui->te->append(QString("\n========================================\n"));
        }
    }

    if (ui->cbtype->currentText() == "sort()") //сортировка пакетов по функции sort()
    {
        if (ui->cb->currentText() == "По длине")
        {
            Packet::choose = 1;
            sort(mPacket.begin(), mPacket.end());
        }
        else if (ui->cb->currentText() == "По времени жизни")
        {
            Packet::choose = 2;
            sort(mPacket.begin(), mPacket.end());
        }
        else if (ui->cb->currentText() == "По адресу получателя")
        {
            Packet::choose = 3;
            sort(mPacket.begin(), mPacket.end());
        }
        else if (ui->cb->currentText() == "По адресу отправителя")
        {
            Packet::choose = 4;
            sort(mPacket.begin(), mPacket.end());
        }
        else if (ui->cb->currentText() == "По длине заголовочной части пакета")
        {
            Packet::choose = 5;
            sort(mPacket.begin(), mPacket.end());
        }
        else if (ui->cb->currentText() == "По контрольной сумме (первый байт контрольной суммы)")
        {
            Packet::choose = 6;
            sort(mPacket.begin(), mPacket.end());
        }
        else if (ui->cb->currentText() == "По контрольной сумме (последний байт контрольной суммы)")
        {
            Packet::choose = 7;
            sort(mPacket.begin(), mPacket.end());
        }
        else if (ui->cb->currentText() == "По типу инкапсулированного пакета(4 - TCP,  17 - UDP)")
        {
            Packet::choose = 8;
            sort(mPacket.begin(), mPacket.end());
        }

        for (int i=0; i<n; i++)
        {
            ui->te->append(QString("===== Пакет №%1 =====").arg(mPacket[i].mIndexes));
            ui->te->append(QString("Длина пакета: %1").arg(mPacket[i].mHeaders->caplen));
            ui->te->append(QString("Получено: %1").arg(mPacket[i].mHeaders->len));
            ui->te->append(QString("Метка времени: %1").arg(mPacket[i].mHeaders->ts.tv_sec));
            ui->te->append(QString("Метка времени (микросек): %1").arg(mPacket[i].mHeaders->ts.tv_usec));

            ui->te->append(QString("========= IP сортировка: ========="));
            ui->te->append(QString("Длина: %1").arg(mPacket[i].mIp->ip_len));
            ui->te->append(QString("Время жизни: %1").arg(mPacket[i].mIp->ip_ttl)); // with 1 january 1970
            ui->te->append(QString("Адрес получателя: %1").arg(mPacket[i].mIp->ip_dst.s_addr));
            ui->te->append(QString("Адрес отправителя: %1").arg(mPacket[i].mIp->ip_src.s_addr));
            ui->te->append(QString("Длина заголовочной части пакета: %1").arg(mPacket[i].mIp->ip_vhl));
            ui->te->append(QString("Контрольная сумма: %1").arg(mPacket[i].mIp->ip_sum));
            ui->te->append(QString("Протокола транспортного уровня: %1").arg(mPacket[i].mIp->ip_p)); // 6 - TCP, 17 - UDP
            ui->te->append(QString("Тип обслуживания: %1").arg(mPacket[i].mIp->ip_tos)); //0-2 приоритет данного IP-сегмент
            ui->te->append(QString("\n========================================\n"));
        }
    }

    if (ui->cbtype->currentText() == "Внешняя") //сортировка пакетов по функции sort()
    {
        filebuf buffer;
        ostream output(&buffer);
        istream input(&buffer);
        filedat = "E:/QtProject/pcapproject/example.dat";
        buffer.open (filedat, ios::in | ios::out | ios::trunc);

        for (int i=0; i<n; i++)
        {
            output << mPacket[i].mIndexes << endl;
            output << mPacket[i].mHeaders->caplen << endl;
            output << mPacket[i].mHeaders->len << endl;
            output << mPacket[i].mHeaders->ts.tv_sec << endl;
            output << mPacket[i].mHeaders->ts.tv_usec << endl;
            output << mPacket[i].mDatas << endl;
            output << mPacket[i].mIp->ip_len << endl;
            output << mPacket[i].mIp->ip_ttl << endl;
            output << mPacket[i].mIp->ip_src.s_addr << endl;
            output << mPacket[i].mIp->ip_dst.s_addr << endl;
            output << mPacket[i].mIp->ip_vhl << endl;
            output << mPacket[i].mIp->ip_sum << endl;
            output << mPacket[i].mIp->ip_p << endl;
            output << mPacket[i].mIp->ip_tos << endl;
            output << endl;
        }

        for (int i=0; i<n; i++)
        {
            input.seekg(0); // указатель на начало
            input >> mPacket[i].mIndexes;
            input >> mPacket[i].mHeaders->caplen;
            input >> mPacket[i].mHeaders->len;
            input >> mPacket[i].mHeaders->ts.tv_sec;
            input >> mPacket[i].mHeaders->ts.tv_usec;
            input >> mPacket[i].mDatas;
            input >> mPacket[i].mIp->ip_len;
            input >> mPacket[i].mIp->ip_ttl;
            input >> mPacket[i].mIp->ip_dst.s_addr;
            input >> mPacket[i].mIp->ip_src.s_addr;
            input >> mPacket[i].mIp->ip_vhl;
            input >> mPacket[i].mIp->ip_sum;
            input >> mPacket[i].mIp->ip_p;
            input >> mPacket[i].mIp->ip_tos;
        }

        input.clear();           // чистим за собой

        if (ui->cb->currentText() == "По длине")
        {
            //Merge (filedat);
        }
    }
}

void MainWindow::Exchange(int i, int j)
{
    std::swap(mPacket[i].mIndexes, mPacket[j].mIndexes);
    std::swap(mPacket[i].mHeaders, mPacket[j].mHeaders);
    std::swap(mPacket[i].mDatas, mPacket[j].mDatas);
    std::swap(mPacket[i].mIp, mPacket[j].mIp);
    // std::swap(mPacket[i].mEthernet, mPacket[j].mEthernet);
    // std::swap(mPacket[i].mTcp, mPacket[j].mTcp);
    // std::swap(mPacket[i].mPayload, mPacket[j].mPayload);
}

//void MainWindow::Merge(const char *filedat)
//{
//    filebuf buffer;
//    ostream output(&buffer);
//    istream input(&buffer);

//    int  a1, a2;
//    int   k, kol, tmp;
//    QFile f(filedat);
//    QFile f1("temp1.dat");
//    QFile f2("temp2.dat");

//    kol = 0;
//    k = 1;

//    while (k < kol)
//    {
//        f.open (QIODevice::ReadWrite | QIODevice::Text);
//        f1.open (QIODevice::ReadWrite | QIODevice::Text);
//        f2.open (QIODevice::ReadWrite | QIODevice::Text);

//        if (!f.atEnd())
//            fscanf(f, "%d", &a1);
//        while (!f.atEnd())
//        {
//            for (int i = 0; i < k && !f.atEnd(); i++)
//            {
//                fprintf(f1, "%d", a1);
//                fscanf(f, "%d", &a1);
//            }
//            for (int j = 0; j < k && !f.atEnd(); j++)
//            {
//                fprintf(f2, "%d", a1);
//                fscanf(f, "%d", &a1);
//            }
//        }

//        f.close();
//        f1.close();
//        f2.close();
//    }
//}

// перегрузка оператора сравнения
bool operator < (Packet &obj1, Packet &obj2)
{
    switch (Packet::choose)
    {
    case 1:
        if (obj1.mIp->ip_len < obj2.mIp->ip_len) return true;
        else return false;
        break;
    case 2:
        if (obj1.mIp->ip_ttl < obj2.mIp->ip_ttl) return true;
        else return false;
        break;
    case 3:
        if (obj1.mIp->ip_dst.s_addr < obj2.mIp->ip_dst.s_addr) return true;
        else return false;
        break;
    case 4:
        if (obj1.mIp->ip_src.s_addr < obj2.mIp->ip_src.s_addr) return true;
        else return false;
        break;
    case 5:
        if (obj1.mIp->ip_vhl < obj2.mIp->ip_vhl) return true;
        else return false;
        break;
    case 6:
        if (obj1.mIp->ip_sum & 0xFF00 < obj2.mIp->ip_sum & 0xFF00) return true;
        else return false;
        break;
    case 7:
        if (obj1.mIp->ip_sum & 0xFF < obj2.mIp->ip_sum & 0xFF) return true;
        else return false;
        break;
    case 8:
        if (obj1.mIp->ip_p < obj2.mIp->ip_p) return true;
        else return false;
        break;
    }
}

// перегрузка оператора сравнения
bool operator < (const Packet &obj1, Packet &obj2)
{
    switch (Packet::choose)
    {
    case 1:
        if (obj1.mIp->ip_len < obj2.mIp->ip_len) return true;
        else return false;
        break;
    case 2:
        if (obj1.mIp->ip_ttl < obj2.mIp->ip_ttl) return true;
        else return false;
        break;
    case 3:
        if (obj1.mIp->ip_dst.s_addr < obj2.mIp->ip_dst.s_addr) return true;
        else return false;
        break;
    case 4:
        if (obj1.mIp->ip_src.s_addr < obj2.mIp->ip_src.s_addr) return true;
        else return false;
        break;
    case 5:
        if (obj1.mIp->ip_vhl < obj2.mIp->ip_vhl) return true;
        else return false;
        break;
    case 6:
        if (obj1.mIp->ip_sum & 0xFF00 < obj2.mIp->ip_sum & 0xFF00) return true;
        else return false;
        break;
    case 7:
        if (obj1.mIp->ip_sum & 0xFF < obj2.mIp->ip_sum & 0xFF) return true;
        else return false;
        break;
    case 8:
        if (obj1.mIp->ip_p < obj2.mIp->ip_p) return true;
        else return false;
        break;
    }
}

// перегрузка оператора сравнения
bool operator < (Packet &obj1, const Packet &obj2)
{
    switch (Packet::choose)
    {
    case 1:
        if (obj1.mIp->ip_len < obj2.mIp->ip_len) return true;
        else return false;
        break;
    case 2:
        if (obj1.mIp->ip_ttl < obj2.mIp->ip_ttl) return true;
        else return false;
        break;
    case 3:
        if (obj1.mIp->ip_dst.s_addr < obj2.mIp->ip_dst.s_addr) return true;
        else return false;
        break;
    case 4:
        if (obj1.mIp->ip_src.s_addr < obj2.mIp->ip_src.s_addr) return true;
        else return false;
        break;
    case 5:
        if (obj1.mIp->ip_vhl < obj2.mIp->ip_vhl) return true;
        else return false;
        break;
    case 6:
        if (obj1.mIp->ip_sum & 0xFF00 < obj2.mIp->ip_sum & 0xFF00) return true;
        else return false;
        break;
    case 7:
        if (obj1.mIp->ip_sum & 0xFF < obj2.mIp->ip_sum & 0xFF) return true;
        else return false;
        break;
    case 8:
        if (obj1.mIp->ip_p < obj2.mIp->ip_p) return true;
        else return false;
        break;
    }
}

// перегрузка оператора сравнения
bool operator < (const Packet &obj1, const Packet &obj2)
{
    switch (Packet::choose)
    {
    case 1:
        if (obj1.mIp->ip_len < obj2.mIp->ip_len) return true;
        else return false;
        break;
    case 2:
        if (obj1.mIp->ip_ttl < obj2.mIp->ip_ttl) return true;
        else return false;
        break;
    case 3:
        if (obj1.mIp->ip_dst.s_addr < obj2.mIp->ip_dst.s_addr) return true;
        else return false;
        break;
    case 4:
        if (obj1.mIp->ip_src.s_addr < obj2.mIp->ip_src.s_addr) return true;
        else return false;
        break;
    case 5:
        if (obj1.mIp->ip_vhl < obj2.mIp->ip_vhl) return true;
        else return false;
        break;
    case 6:
        if (obj1.mIp->ip_sum & 0xFF00 < obj2.mIp->ip_sum & 0xFF00) return true;
        else return false;
        break;
    case 7:
        if (obj1.mIp->ip_sum & 0xFF < obj2.mIp->ip_sum & 0xFF) return true;
        else return false;
        break;
    case 8:
        if (obj1.mIp->ip_p < obj2.mIp->ip_p) return true;
        else return false;
        break;
    }
}
