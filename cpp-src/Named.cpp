
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

#define EXTERNAL_ADDRESS  "10.3.9.4"	//外部DNS服务器地址
#define LOCAL_ADDRESS     "127.0.0.1"	//本地DNS服务器地址
#define DNS_PORT 53						//进行DNS服务的53端口
#define BUF_SIZE 512
#define LENGTH 65
#define NUMBER 1000
#define START 13						//DNS报文头部有12个字节，第13个字节起为查询问题，也即url起始处

char url[NUMBER];

char *path = "D:\\dnsrelay.txt";

//解析表结构
class DomainIP
{
public:
	string domain;
	int IP[4];
};
vector<DomainIP> DNSTable;

//ID转换结构
typedef struct IDtranslate
{
	unsigned short oldID;			//原有ID
	BOOL b;						    //标记是否完成解析
	SOCKADDR_IN client;				//请求者套接字地址
} IDTrans;
IDTrans IDList[NUMBER];	        //ID转换表
int IDcount = 0;					//转换表中的条目个数

//获取本地dns解析表
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

//从请求报文中提取url
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

//在本地dns解析表中查找看是否存在要解析的域名，如果存在则返回行号
int local_search(char *url, int n)
{
	int find = -1;
	char* idomain;
	//cout << url << endl;
	for (int i = 0; i<n; i++)
	{
		idomain = (char *)DNSTable[i].domain.c_str();	//string和char*不能直接比较，要转换一下
		if (strcmp(idomain, url) == 0)
		{
			find = i;
			break;
		}
	}
	return find;
}

// id 转换
unsigned short IDConvert(unsigned short oID, SOCKADDR_IN client, bool b)
{
	IDList[IDcount].oldID = oID;
	IDList[IDcount].b = b;
	IDList[IDcount].client = client;
	IDcount = (IDcount + 1) % NUMBER;          //防止越界

	return (short)(IDcount - 1);          //把表中的下表作为新的ID传送回去、
}

//显示监听内容，type = 1显示到屏幕，type = 2输出到log文件
void log(int line, int type)	//type = 1 show in screen, 2 write to .log
{
	if (type == 1)
	{
		//在表中没有找到DNS请求中的域名
		if (line == -1)
		{
			//中继功能
			cout << "Relay" << "\t" << url << endl;

		}

		//在表中找到DNS请求中的域名
		else {
			if (DNSTable[line].IP[0] == 0 && DNSTable[line].IP[1] == 0 && DNSTable[line].IP[2] == 0 && DNSTable[line].IP[3] == 0)
			{
				//屏蔽功能 不良网站拦截
				cout << "Block" << "\t" << url << endl;
			}

			//普通IP地址
			else {
				//本地功能
				cout << "Local" << "\t" << url << "\t"
					<< DNSTable[line].IP[0] << "." << DNSTable[line].IP[1] << "." << DNSTable[line].IP[2] << "." << DNSTable[line].IP[3] << endl;
			}
		}
	}
	else if (type == 2)
	{
		ofstream fout("D:\\dns.log", ios::app);
		//在表中没有找到DNS请求中的域名
		if (line == -1)
		{
			//中继功能
			fout << "Relay" << "\t" << url << endl;
		}

		//在表中找到DNS请求中的域名
		else {
			if (DNSTable[line].IP[0] == 0 && DNSTable[line].IP[1] == 0 && DNSTable[line].IP[2] == 0 && DNSTable[line].IP[3] == 0)
			{
				//屏蔽功能 不良网站拦截
				fout << "Block" << "\t" << url << endl;
			}

			//普通IP地址
			else {
				//本地功能
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

	//提供log显示的多种方式， 默认存到文件
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

	records = getDNSTable();   //读入list 并返回记录个数
	sock = socket(AF_INET, SOCK_DGRAM, 0);	//udp包

	//设置本地监听所有地址送来的53号端口的信息
	local.sin_family = AF_INET;
	local.sin_port = htons(DNS_PORT);
	local.sin_addr.S_un.S_addr = htonl(INADDR_ANY);	//S_un.S_addr:以u_long类型存储的IPv4地址

	//设置外部服务器的监听参数
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
					//id记录
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
					recvbuf[4] = 0x00, recvbuf[5] = 0x01; // 首部Questions count字段填充为  0x0001 
					recvbuf[6] = 0x00, recvbuf[7] = 0x01; // 首部Answer RRS字段填充为  0001 
					recvbuf[8] = 0x00, recvbuf[9] = 0x00; // 首部Authority RRS字段填充为  0000   
					recvbuf[10] = 0x00, recvbuf[11] = 0x00;  // 首部Additional RRS字段填充为  0000 

					// Answer域
					recvbuf[recv] = 0xc0;	 //  recv是查询报的长度，在其后填充Answer 
					recvbuf[recv + 1] = 0x0c;  // 这两个字节是域名 
					recvbuf[recv + 2] = 0x00;
					recvbuf[recv + 3] = 0x01;  // 网络类型type 为A(0x0001)，代表IPv4 
					recvbuf[recv + 4] = 0x00;
					recvbuf[recv + 5] = 0x01;  // 网络级别class 为IN(0x0001)，代表Internet 
					recvbuf[recv + 6] = 0x00;
					recvbuf[recv + 7] = 0x00;
					recvbuf[recv + 8] = 0x02;
					recvbuf[recv + 9] = 0x58;  // 以上四个字节为生命期TTL，0x0258秒，为10分钟 
					recvbuf[recv + 10] = 0x00;
					recvbuf[recv + 11] = 0x04; // 以上2字节是Data Length，4byte，32位IPv4 地址 

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
