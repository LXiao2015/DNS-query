
#include "stdafx.h"
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <iostream>
#include <fstream>
#include <iomanip>
#include <vector>
#include <string>
#include <winsock2.h> 
#include <windows.h>  
#pragma  comment(lib, "Ws2_32.lib")
using namespace std;

#define EXTERNAL_ADDRESS  "10.3.9.4"	//�ⲿDNS��������ַ
#define LOCAL_ADDRESS     "127.0.0.1"	//����DNS��������ַ
#define DNS_PORT 53						//����DNS�����53�˿�
#define BUF_SIZE 512
#define LENGTH 65
#define NUMBER 1000
#define START 13						//DNS����ͷ����12���ֽڣ���13���ֽ���Ϊ��ѯ���⣬Ҳ��url��ʼ��

char url[NUMBER];

char *path = "D:\\dnsrelay.txt";

//������ṹ
class DomainIP
{
public:
	string domain;
	int IP[4];
};
vector<DomainIP> DNSTable;

//IDת���ṹ
typedef struct IDtranslate
{
	unsigned short oldID;			//ԭ��ID
	BOOL b;						    //����Ƿ���ɽ���
	SOCKADDR_IN client;				//�������׽��ֵ�ַ
} IDTrans;
IDTrans IDList[NUMBER];	        //IDת����
int IDcount = 0;					//ת�����е���Ŀ����

//��ȡ����dns������
int getDNSTable(void)
{
	fstream fs;
	ofstream out;
	char ch;
	DomainIP i;
	fs.open("dnsrelay.txt");

	if (fs.is_open() == 1)
	{
		while (!fs.eof())
		{
			fs >> i.IP[0];
			fs >> ch;
			fs >> i.IP[1];
			fs >> ch;
			fs >> i.IP[2];
			fs >> ch;
			fs >> i.IP[3];
			fs >> i.domain;
			i.domain = i.domain + '\0';

			DNSTable.push_back(i);
		}
		if (DNSTable.size() != 0)
			DNSTable.pop_back();
	}
	else
	{
		cout << "Open DNS File failed!" << endl;
	}

	cout << DNSTable.size() << " records have been loaded." << endl;
	fs.close();
	return DNSTable.size();

}

//������������ȡurl
char* getUrl(char *recvbuf)
{
	char *domain = (char *)malloc(sizeof(char) * NUMBER);
	int i = START;
	for (i; recvbuf[i] != '\0'; i++)
	{
		domain[i] = recvbuf[i];
	}
	domain[i] = '\0';
	return domain;
}

//�ڱ���dns�������в��ҿ��Ƿ����Ҫ��������������������򷵻��к�
int local_search(char *url, int n)
{
	int find = -1;
	char* idomain;
	//cout << url << endl;
	for (int i = 0; i<n; i++)
	{
		idomain = (char *)DNSTable[i].domain.c_str();	//string��char*����ֱ�ӱȽϣ�Ҫת��һ��
		if (strcmp(idomain, url) == 0)
		{
			find = i;
			break;
		}
	}
	return find;
}

// id ת��
unsigned short IDConvert(unsigned short oID, SOCKADDR_IN client, bool b)
{
	IDList[IDcount].oldID = oID;
	IDList[IDcount].b = b;
	IDList[IDcount].client = client;
	IDcount = (IDcount + 1) % NUMBER;          //��ֹԽ��

	return (short)(IDcount - 1);          //�ѱ��е��±���Ϊ�µ�ID���ͻ�ȥ��
}

//��ʾ�������ݣ�type = 1��ʾ����Ļ��type = 2�����log�ļ�
void log(int line, int type)	//type = 1 show in screen, 2 write to .log
{
	if (type == 1)
	{
		//�ڱ���û���ҵ�DNS�����е�����
		if (line == -1)
		{
			//�м̹���
			cout << "Relay" << "\t" << url << endl;

		}

		//�ڱ����ҵ�DNS�����е�����
		else {
			if (DNSTable[line].IP[0] == 0 && DNSTable[line].IP[1] == 0 && DNSTable[line].IP[2] == 0 && DNSTable[line].IP[3] == 0)
			{
				//���ι��� ������վ����
				cout << "Block" << "\t" << url << endl;
			}

			//��ͨIP��ַ
			else {
				//���ع���
				cout << "Local" << "\t" << url << "\t"
					<< DNSTable[line].IP[0] << "." << DNSTable[line].IP[1] << "." << DNSTable[line].IP[2] << "." << DNSTable[line].IP[3] << endl;
			}
		}
	}
	else if (type == 2)
	{
		ofstream fout("D:\\dns.log", ios::app);
		//�ڱ���û���ҵ�DNS�����е�����
		if (line == -1)
		{
			//�м̹���
			fout << "Relay" << "\t" << url << endl;
		}

		//�ڱ����ҵ�DNS�����е�����
		else {
			if (DNSTable[line].IP[0] == 0 && DNSTable[line].IP[1] == 0 && DNSTable[line].IP[2] == 0 && DNSTable[line].IP[3] == 0)
			{
				//���ι��� ������վ����
				fout << "Block" << "\t" << url << endl;
			}

			//��ͨIP��ַ
			else {
				//���ع���
				fout << "Local" << "\t" << url << "\t"
					<< DNSTable[line].IP[0] << "." << DNSTable[line].IP[1] << "." << DNSTable[line].IP[2] << "." << DNSTable[line].IP[3] << endl;
			}
		}
		fout.close();
	}
	else
		cout << "Out type error." << endl;
}

int main(int argc, char *argv[])
{

	WSADATA wsadata;
	SOCKET sock;
	SOCKADDR_IN local, external, client;


	char recvbuf[BUF_SIZE];
	int recv, send;
	int n_client;
	int records;
	int type = 1;

	if (WSAStartup(MAKEWORD(2, 2), &wsadata) != 0)
	{
		cout << "Link failed!" << endl;
		exit(1);
	}

	//�ṩlog��ʾ�Ķ��ַ�ʽ�� Ĭ�ϴ浽�ļ�
	if (argc == 2)
	{
		if (strcmp(argv[1], "-l") == 0)
		{
			type = 2;
		}
		else if (strcmp(argv[1], "-d") == 0)
			type = 1;
		else
			type = 1;
	}
	else
		type = 1;

	records = getDNSTable();   //����list �����ؼ�¼����
	sock = socket(AF_INET, SOCK_DGRAM, 0);	//udp��

	//���ñ��ؼ������е�ַ������53�Ŷ˿ڵ���Ϣ
	local.sin_family = AF_INET;
	local.sin_port = htons(DNS_PORT);
	local.sin_addr.S_un.S_addr = htonl(INADDR_ANY);	//S_un.S_addr:��u_long���ʹ洢��IPv4��ַ

	//�����ⲿ�������ļ�������
	external.sin_family = AF_INET;
	external.sin_port = htons(DNS_PORT);
	external.sin_addr.S_un.S_addr = inet_addr(EXTERNAL_ADDRESS);
	
	unsigned short *pID;

	if (bind(sock, (SOCKADDR*)&local, sizeof(local)) == SOCKET_ERROR)
	{
		cout << "Bind failed." << endl;
		exit(1);
	}
	else
		cout << "Bind success." << endl;

	while (true)
	{
		memset(recvbuf, 0, BUF_SIZE);
		n_client = sizeof(SOCKADDR);

		recv = recvfrom(sock, recvbuf, sizeof(recvbuf), 0, (SOCKADDR*)&client, &n_client);
		if (recv == SOCKET_ERROR)
		{
			cout << "No data received." << endl;
			continue;
		}
		else if (recv == 0)
		{
			cout << "Link abort." << endl;
			break;
		}
		else
		{
			if (ntohs(client.sin_port) == 53)
			{
				pID = (unsigned short *)malloc(sizeof(unsigned short));
				memcpy(pID, recvbuf, sizeof(unsigned short));
				int m = *pID;
				unsigned short oID = IDList[m].oldID;
				memcpy(recvbuf, &oID, sizeof(unsigned short));
				IDList[m].b = TRUE;
				client = IDList[m].client;			
				send = sendto(sock, recvbuf, recv, 0, (SOCKADDR *)&client, sizeof(client));
				
				if (send == SOCKET_ERROR)
				{
					cout << "Send failed." << endl;
					continue;
				}
				else if (send == 0)
				{
					cout << "Link abort." << endl;
					break;
				}
				free(pID);
			}
			else
			{
				int i = 13;
				for (i = 13; recvbuf[i] != '\0'; i++)
				{
					if (recvbuf[i]>' ')
						url[i - 13] = recvbuf[i];
					else
						url[i - 13] = '.';
				}
				url[i - 13] = '\0';

				int find = local_search(url, records);

				if (find == -1)
				{
					//id��¼
					pID = (unsigned short *)malloc(sizeof(unsigned short));
					memcpy(pID, recvbuf, sizeof(unsigned short));
					unsigned short nID = IDConvert(*pID, client, FALSE);
					memcpy(recvbuf, &nID, sizeof(unsigned short));

					log(find, type);

					send = sendto(sock, recvbuf, recv, 0, (SOCKADDR *)&external, sizeof(external));
					if (send == SOCKET_ERROR)
					{
						cout << "Send failed." << endl;
						continue;
					}
					else if (send == 0)
					{
						cout << "Link abort" << endl;
						break;
					}
				}
				else
				{
					unsigned short *pID = (unsigned short *)malloc(sizeof(unsigned short));
					memcpy(pID, recvbuf, sizeof(unsigned short));

					log(find, type);
					
					if (DNSTable[find].IP[0] == 0 && DNSTable[find].IP[1] == 0 && DNSTable[find].IP[2] == 0 && DNSTable[find].IP[3] == 0)
					{
						recvbuf[2] = 0x81;
						recvbuf[3] = 0x83;
					}
					else
					{
						recvbuf[2] = 0x81;
						recvbuf[3] = 0x80;
					}
					recvbuf[4] = 0x00, recvbuf[5] = 0x01; // �ײ�Questions count�ֶ����Ϊ  0x0001 
					recvbuf[6] = 0x00, recvbuf[7] = 0x01; // �ײ�Answer RRS�ֶ����Ϊ  0001 
					recvbuf[8] = 0x00, recvbuf[9] = 0x00; // �ײ�Authority RRS�ֶ����Ϊ  0000   
					recvbuf[10] = 0x00, recvbuf[11] = 0x00;  // �ײ�Additional RRS�ֶ����Ϊ  0000 

					// Answer��
					recvbuf[recv] = 0xc0;	 //  recv�ǲ�ѯ���ĳ��ȣ���������Answer 
					recvbuf[recv + 1] = 0x0c;  // �������ֽ������� 
					recvbuf[recv + 2] = 0x00;
					recvbuf[recv + 3] = 0x01;  // ��������type ΪA(0x0001)������IPv4 
					recvbuf[recv + 4] = 0x00;
					recvbuf[recv + 5] = 0x01;  // ���缶��class ΪIN(0x0001)������Internet 
					recvbuf[recv + 6] = 0x00;
					recvbuf[recv + 7] = 0x00;
					recvbuf[recv + 8] = 0x02;
					recvbuf[recv + 9] = 0x58;  // �����ĸ��ֽ�Ϊ������TTL��0x0258�룬Ϊ10���� 
					recvbuf[recv + 10] = 0x00;
					recvbuf[recv + 11] = 0x04; // ����2�ֽ���Data Length��4byte��32λIPv4 ��ַ 

					recvbuf[recv + 12] = DNSTable[find].IP[0];
					recvbuf[recv + 13] = DNSTable[find].IP[1];
					recvbuf[recv + 14] = DNSTable[find].IP[2];
					recvbuf[recv + 15] = DNSTable[find].IP[3];

					send = sendto(sock, recvbuf, recv + 16, 0, (SOCKADDR *)&client, sizeof(client));

				}
			}

		}

	}
	closesocket(sock);

	WSACleanup();
	return 0;
}
