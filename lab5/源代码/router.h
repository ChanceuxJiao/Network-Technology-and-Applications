#pragma once
#define _CRT_SECURE_NO_WARNINGS
#define _WINSOCK_DEPRECATED_NO_WARNINGS
#include <Winsock2.h>
//#include<iostream>
#include "stdio.h"
//#include<time.h>
#include <string.h>
//#include <arpa/inet.h> // 包含头文件


#pragma comment(lib,"ws2_32.lib")
#pragma comment(lib, "packet.lib")
#pragma comment(lib,"wpcap.lib")
#pragma comment(lib,"wsock32.lib")

#include <Winsock2.h>
//#include<iostream>
#include "pcap.h"
#include "stdio.h"
//#include<time.h>
#include <string.h>
//#include "log.h"//日志

#pragma comment(lib,"ws2_32.lib")
#pragma comment(lib, "packet.lib")
#pragma comment(lib,"wpcap.lib")
#pragma comment(lib,"wsock32.lib")
#pragma warning(disable : 4996)

#pragma pack(1)//字节对齐方式

typedef struct Frame_Header {		//帧首部
	BYTE DesMAC[6];//目的地址
	BYTE SrcMAC[6];//源地址
	WORD FrameType;//帧类型
}Frame_Header;

typedef struct IP_Header {		//IP首部
	BYTE Ver_HLen;//IP协议版本和IP首部长度：高4位为版本，低4位为首部的长度
	BYTE TOS;//服务类型
	WORD TotalLen;//总长度
	WORD ID;//标识
	WORD Flag_Segment;//标志 片偏移
	BYTE TTL;//生存周期
	BYTE Protocol;//协议
	WORD Checksum;//头部校验和
	u_int SrcIP;//源IP
	u_int DstIP;//目的IP
}IP_Header;

typedef struct ARP_Header {//IP首部
	Frame_Header FrameHeader;
	WORD HardwareType;//硬件类型
	WORD ProtocolType;//协议类型
	BYTE HLen;//硬件地址长度
	BYTE PLen;//协议地址长度
	WORD Operation;//操作类型
	BYTE SendHa[6];//发送方MAC地址
	DWORD SendIP;//发送方IP地址
	BYTE RecvHa[6];//接收方MAC地址
	DWORD RecvIP;//接收方IP地址
}ARP_Header;

typedef struct Datagram {		//数据包
	Frame_Header FrameHeader;
	IP_Header IPHeader;
}Datagram;

typedef struct ICMP_Datagram {//ICMP_Datagram报文
	Frame_Header FrameHeader;
	IP_Header IPHeader;
	char buf[0x80];
}ICMP_Datagram_t;

#pragma pack()//恢复缺省对齐方式

class arpitem
{
public:
	DWORD ip;        // ARP表项的IPv4地址
	BYTE mac[6];     // ARP表项的MAC地址
};

class ipitem
{
public:
	DWORD sourceip, destip;     // 源IP和目的IP地址
	BYTE smac[6], dmac[6];  // 源MAC和目的MAC地址
};

class log_print //日志
{
public:
	static FILE* logfile;            // 静态文件指针，指向日志文件
	log_print()
	{
		logfile = fopen("mylog.txt", "a+");  // 以追加模式打开或创建"mylog.txt"文件
	}

	~log_print()
	{
		fclose(logfile);  // 在对象销毁时关闭文件
	}

	// 用于记录ARP数据包信息的函数
	static void ARP_print(ARP_Header* t)
	{
		// 打印一条消息，指示ARP表项缺失，并且正在发送ARP数据包以获取IP地址与MAC地址的映射关系
		fprintf(logfile, "ARP包缺少相关表项，发送ARP包获取IP地址与MAC地址映射关系...\n");

		// 打印ARP数据包信息
		// 将IP地址从网络字节序转换为点分十进制，并打印
		in_addr addr;
		addr.s_addr = t->SendIP;
		char* temp = inet_ntoa(addr);
		fprintf(logfile, "IP:");
		fprintf(logfile, "%s\t", temp);

		// 打印MAC地址
		fprintf(logfile, "MAC:");
		for (int i = 0; i < 6; i++)
		{
			fprintf(logfile, "%02x:", t->SendHa[i]);
		}
		fprintf(logfile, "\n\n");
		//printf("end\n");
	}

	// 用于记录IP数据包信息的函数
	static void IP_print(int a, Datagram* t)
	{
		// 根据参数a的值打印相应的消息，表明是接收IP数据包还是转发IP数据包
		if (a == 0)
		{
			fprintf(logfile, "接收IP数据包\n");
		}
		else
		{
			fprintf(logfile, "转发IP数据包\n");
		}

		// 将源IP地址从网络字节序转换为点分十进制，并打印
		in_addr addr;
		addr.s_addr = t->IPHeader.SrcIP;
		char* temp = inet_ntoa(addr);
		fprintf(logfile, "源IP：");
		fprintf(logfile, "%s\t", temp);

		// 打印目的IP地址
		fprintf(logfile, "目的IP：");
		addr.s_addr = t->IPHeader.DstIP;
		temp = inet_ntoa(addr);
		fprintf(logfile, "%s\t", temp);

		// 打印源MAC地址
		fprintf(logfile, "源MAC：");
		for (int i = 0; i < 6; i++)
			fprintf(logfile, "%02x:", t->FrameHeader.SrcMAC[i]);
		fprintf(logfile, "\t");

		// 打印目的MAC地址
		fprintf(logfile, "目的MAC：");
		for (int i = 0; i < 6; i++)
			fprintf(logfile, "%02x:", t->FrameHeader.DesMAC[i]);
		fprintf(logfile, "\n\n");
		//printf("end\n");
	}
};


char my_IP[10][20];
char mask[10][20];
BYTE my_MAC[6];
pcap_t* adhandle;
//多线程
HANDLE hThread;
DWORD dwThreadId;
int choose_dev;
//int log_print::num = 0;
//log_print log_print::diary[50] = {};
FILE* log_print::logfile = nullptr;
log_print mylog;
BYTE broadcast[6] = { 0xff,0xff,0xff,0xff,0xff,0xff };



#pragma pack(1)
class RouterItem//路由表表项
{
public:
	DWORD mask;//掩码
	DWORD net;//目的网络
	DWORD nextip;//下一跳
	BYTE nextmac[6];
	int index;//第几条
	int type;//0为直接连接，1为用户添加
	RouterItem* nextitem;//采用链表形式存储
	RouterItem()
	{
		memset(this, 0, sizeof(*this));//全部初始化为0
	}
	void PrintItem()//打印表项内容：掩码、目的网络、下一跳IP、类型
	{
		in_addr addr;
		printf("%d ", index);
		addr.s_addr = mask;
		char* temp = inet_ntoa(addr);
		printf("%s\t", temp);
		addr.s_addr = net;
		temp = inet_ntoa(addr);
		printf("%s\t", temp);
		addr.s_addr = nextip;
		temp = inet_ntoa(addr);
		printf("%s\t", temp);
		printf("%d\n", type);
	}
};
#pragma pack()

#pragma pack(1)
class RouterTable//路由表
{
public:
	RouterItem* head, * tail;
	int num;//条数
	RouterTable()//初始化，添加直接相连的网络
	{
		head = new RouterItem;
		tail = new RouterItem;
		head->nextitem = tail;
		num = 0;
		for (int i = 0; i < 2; i++)
		{
			RouterItem* temp = new RouterItem;
			temp->net = (inet_addr(my_IP[i])) & (inet_addr(mask[i]));//本机网卡的ip和掩码进行按位与即为所在网络
			temp->mask = inet_addr(mask[i]);
			temp->type = 0;//0表示直接连接，不可删除
			this->Add_ritem(temp);
		}
	}


	// 路由表的添加函数
	void Add_ritem(RouterItem* a)
	{
		RouterItem* pointer;

		// 如果a的type为0，表示需要插入到链表头部
		if (!a->type)
		{
			// 将a插入到链表头部
			a->nextitem = head->nextitem;
			head->nextitem = a;
			a->type = 0;
		}
		else // 按照掩码由长至短找到合适的位置
		{
			for (pointer = head->nextitem; pointer != tail && pointer->nextitem != tail; pointer = pointer->nextitem)
			{
				// 找到掩码比a的掩码大，且掩码比下一项的掩码小的位置
				if (a->mask < pointer->mask && a->mask >= pointer->nextitem->mask || pointer->nextitem == tail)
				{
					break;
				}
			}
			// 将a插入到找到的位置
			a->nextitem = pointer->nextitem;
			pointer->nextitem = a;
		}

		// 重新设置每个节点的index
		RouterItem* p = head->nextitem;
		for (int i = 0; p != tail; p = p->nextitem, i++)
		{
			p->index = i;
		}

		// 增加路由表中的条目数量
		num++;
	}



	// 路由表的删除函数
	void Delate_ritem(int index)
	{
		// 循环遍历链表
		for (RouterItem* t = head; t->nextitem != tail; t = t->nextitem)
		{
			// 检查链表中每个节点的index是否等于传入的index
			if (t->nextitem->index == index)
			{
				// 如果找到匹配的index
				if (t->nextitem->type == 0)
				{
					// 如果该项的type为0，表示不可删除，输出提示信息并返回
					printf("该项不可删除\n");
					return;
				}
				else
				{
					// 否则，从链表中删除该项
					t->nextitem = t->nextitem->nextitem;
					return;
				}
			}
		}

		// 如果循环结束后仍未找到匹配的index，输出提示信息
		printf("无该表项\n");
	}


	void print()
	{
		for (RouterItem* p = head->nextitem; p != tail; p = p->nextitem)
		{
			p->PrintItem();
		}
	}

	// 查找最长前缀，返回下一跳的IP地址
	DWORD RouterFind(DWORD ip)
	{
		// 循环遍历路由表，从头节点的下一个节点开始，直到尾节点
		for (RouterItem* t = head->nextitem; t != tail; t = t->nextitem)
		{
			// 检查传入的IP地址是否匹配当前路由表项的网络部分
			if ((t->mask & ip) == t->net)
			{
				// 如果匹配，返回该路由表项的下一跳IP地址
				return t->nextip;
			}
		}

		// 如果循环结束后仍未找到匹配的项，返回-1表示未找到
		return -1;
	}

};
#pragma pack()


//获取其他设备的IP地址与MAC地址映射
void ARP_operation(DWORD ip0, BYTE mac[])
{
	ARP_Header ARP_datagram;
	//将APRFrame.FrameHeader.DesMAC设置为广播地址
	for (int i = 0; i < 6; i++)
		ARP_datagram.FrameHeader.DesMAC[i] = 0xff;
	//将APRFrame.FrameHeader.SrcMAC设置为本机网卡的MAC地址
	for (int i = 0; i < 6; i++)
	{
		ARP_datagram.FrameHeader.SrcMAC[i] = my_MAC[i];
		ARP_datagram.SendHa[i] = my_MAC[i];
	}
	ARP_datagram.FrameHeader.FrameType = htons(0x0806);//帧类型为ARP
	ARP_datagram.HardwareType = htons(0x0001);//硬件类型为以太网
	ARP_datagram.ProtocolType = htons(0x0800);//协议类型为IP
	ARP_datagram.HLen = 6;//硬件地址长度为6
	ARP_datagram.PLen = 4;//协议地址长为4
	ARP_datagram.Operation = htons(0x0001);//操作为ARP请求
	//将ARP_datagram.SendIP设置为本机网卡上绑定的IP地址
	ARP_datagram.SendIP = inet_addr(my_IP[0]);
	//将ARP_datagram.RecvHa设置为0
	for (int i = 0; i < 6; i++)
	{
		ARP_datagram.RecvHa[i] = 0;
	}
	//将ARP_datagram.RecvIP设置为请求的IP地址
	ARP_datagram.RecvIP = ip0;
	memset(mac, 0, sizeof(mac));

	//发送ARP数据包
	int send_ARP_succeed = pcap_sendpacket(adhandle, (u_char*)&ARP_datagram, sizeof(ARP_Header));
		if (send_ARP_succeed != 0)
		{
			printf("发送错误\n");
			return;
		}
		else
		{
			while (1)//循环接收数据包
			{
				pcap_pkthdr* arp_header;
				const u_char* arp_data;
				int recv_succeed = pcap_next_ex(adhandle, &arp_header, &arp_data);
				if (recv_succeed == 1)
				{
					ARP_Header* arpPacket = (ARP_Header*)arp_data;

					//帧类型为 ARP 协议类型,操作码为 ARP 回复
					if (ntohs(arpPacket->FrameHeader.FrameType) == 0x0806 && ntohs(arpPacket->Operation) == 0x0002)
					{//输出目的MAC地址
							mylog.ARP_print(arpPacket);
							//获得收包的源MAC地址
							for (int i = 0; i < 6; i++)
								mac[i] = arpPacket->FrameHeader.SrcMAC[i];
							break;
						
					}
				}
			}
		}
}




#pragma pack(1)
class ArpTable//ARP表（将IP和MAC的对应关系存储在一张表里）
{
public:
	DWORD ip;
	BYTE mac[6];
	static int num;

	//增加自己的ARP表项
	static void Insert_my_Arp(DWORD ip, BYTE mac[6])
	{
		arptable[num].ip = ip;
		memcpy(arptable[num].mac, mac, 6);
		num++;
	}


	//增加其他的ARP表项
	static void Insert_other_Arp(DWORD ip, BYTE mac[6])
	{
		arptable[num].ip = ip;
		ARP_operation(ip, arptable[num].mac);//找到相应的MAC地址
		memcpy(mac, arptable[num].mac, 6);
		num++;
	}


	// 查找ARP表中是否存在指定IP，如果存在则将对应的MAC地址复制到参数mac中
	static int FindArp(DWORD ip, BYTE mac[6])
	{
		// 初始化mac数组为0
		memset(mac, 0, 6);

		// 循环遍历ARP表中的每一项
		for (int i = 0; i < num; i++)
		{
			// 检查当前ARP表项的IP是否与传入的IP相匹配
			if (ip == arptable[i].ip)
			{
				// 如果匹配，将该ARP表项的MAC地址复制到参数mac中
				memcpy(mac, arptable[i].mac, 6);

				// 返回1表示找到了匹配的ARP表项
				return 1;
			}
		}

		// 如果循环结束后仍未找到匹配的项，返回0表示未找到
		return 0;
	}



	// 打印ARP表
	static void PrintArpTable() {
		// 输出提示信息
		printf("ARP Table:\n");

		// 循环遍历ARP表中的每一项
		for (int i = 0; i < num; i++) {
			// 使用 inet_ntoa 将 DWORD 类型的 IP 地址转换为字符串形式
			in_addr addr;
			addr.s_addr = arptable[i].ip;
			char* ipStr = inet_ntoa(addr);

			// 打印当前ARP表项的IP地址
			printf("IP: %s\tMAC: ", ipStr);

			// 循环遍历当前ARP表项的MAC地址
			for (int j = 0; j < 6; j++) {
				// 打印MAC地址的每一字节，用十六进制表示，并在字节之间添加冒号
				printf("%02X", static_cast<int>(arptable[i].mac[j]));
				if (j < 5) printf(":");
			}

			// 换行，表示当前ARP表项打印完毕
			printf("\n");
		}
	}



}arptable[50];
#pragma pack()

int ArpTable::num = 0;
