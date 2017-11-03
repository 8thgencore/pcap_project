# pcap_project

Для корректной работы необходимо подключить WpdPack

Скачать: 
https://www.winpcap.org/devel.htm

Подключение:
Прописываем в файле pcap_sort.pro путь к библиотеке

INCLUDEPATH += "E:\..\WpdPack\Include"

LIBS += -L"E:\..\WpdPack\Lib" -lwpcap -lpacket
