#pragma once
#define _CRT_SECURE_NO_WARNINGS
#define _WINSOCK_DEPRECATED_NO_WARNINGS
#include <Winsock2.h>
//#include<iostream>
#include "stdio.h"
//#include<time.h>
#include <string.h>
//#include <arpa/inet.h> // ����ͷ�ļ�


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
//#include "log.h"//��־

#pragma comment(lib,"ws2_32.lib")
#pragma comment(lib, "packet.lib")
#pragma comment(lib,"wpcap.lib")
#pragma comment(lib,"wsock32.lib")
#pragma warning(disable : 4996)

#pragma pack(1)//�ֽڶ��뷽ʽ

typedef struct Frame_Header {		//֡�ײ�
	BYTE DesMAC[6];//Ŀ�ĵ�ַ
	BYTE SrcMAC[6];//Դ��ַ
	WORD FrameType;//֡����
}Frame_Header;

typedef struct IP_Header {		//IP�ײ�
	BYTE Ver_HLen;//IPЭ��汾��IP�ײ����ȣ���4λΪ�汾����4λΪ�ײ��ĳ���
	BYTE TOS;//��������
	WORD TotalLen;//�ܳ���
	WORD ID;//��ʶ
	WORD Flag_Segment;//��־ Ƭƫ��
	BYTE TTL;//��������
	BYTE Protocol;//Э��
	WORD Checksum;//ͷ��У���
	u_int SrcIP;//ԴIP
	u_int DstIP;//Ŀ��IP
}IP_Header;

typedef struct ARP_Header {//IP�ײ�
	Frame_Header FrameHeader;
	WORD HardwareType;//Ӳ������
	WORD ProtocolType;//Э������
	BYTE HLen;//Ӳ����ַ����
	BYTE PLen;//Э���ַ����
	WORD Operation;//��������
	BYTE SendHa[6];//���ͷ�MAC��ַ
	DWORD SendIP;//���ͷ�IP��ַ
	BYTE RecvHa[6];//���շ�MAC��ַ
	DWORD RecvIP;//���շ�IP��ַ
}ARP_Header;

typedef struct Datagram {		//���ݰ�
	Frame_Header FrameHeader;
	IP_Header IPHeader;
}Datagram;

typedef struct ICMP_Datagram {//ICMP_Datagram����
	Frame_Header FrameHeader;
	IP_Header IPHeader;
	char buf[0x80];
}ICMP_Datagram_t;

#pragma pack()//�ָ�ȱʡ���뷽ʽ

class arpitem
{
public:
	DWORD ip;        // ARP�����IPv4��ַ
	BYTE mac[6];     // ARP�����MAC��ַ
};

class ipitem
{
public:
	DWORD sourceip, destip;     // ԴIP��Ŀ��IP��ַ
	BYTE smac[6], dmac[6];  // ԴMAC��Ŀ��MAC��ַ
};

class log_print //��־
{
public:
	static FILE* logfile;            // ��̬�ļ�ָ�룬ָ����־�ļ�
	log_print()
	{
		logfile = fopen("mylog.txt", "a+");  // ��׷��ģʽ�򿪻򴴽�"mylog.txt"�ļ�
	}

	~log_print()
	{
		fclose(logfile);  // �ڶ�������ʱ�ر��ļ�
	}

	// ���ڼ�¼ARP���ݰ���Ϣ�ĺ���
	static void ARP_print(ARP_Header* t)
	{
		// ��ӡһ����Ϣ��ָʾARP����ȱʧ���������ڷ���ARP���ݰ��Ի�ȡIP��ַ��MAC��ַ��ӳ���ϵ
		fprintf(logfile, "ARP��ȱ����ر������ARP����ȡIP��ַ��MAC��ַӳ���ϵ...\n");

		// ��ӡARP���ݰ���Ϣ
		// ��IP��ַ�������ֽ���ת��Ϊ���ʮ���ƣ�����ӡ
		in_addr addr;
		addr.s_addr = t->SendIP;
		char* temp = inet_ntoa(addr);
		fprintf(logfile, "IP:");
		fprintf(logfile, "%s\t", temp);

		// ��ӡMAC��ַ
		fprintf(logfile, "MAC:");
		for (int i = 0; i < 6; i++)
		{
			fprintf(logfile, "%02x:", t->SendHa[i]);
		}
		fprintf(logfile, "\n\n");
		//printf("end\n");
	}

	// ���ڼ�¼IP���ݰ���Ϣ�ĺ���
	static void IP_print(int a, Datagram* t)
	{
		// ���ݲ���a��ֵ��ӡ��Ӧ����Ϣ�������ǽ���IP���ݰ�����ת��IP���ݰ�
		if (a == 0)
		{
			fprintf(logfile, "����IP���ݰ�\n");
		}
		else
		{
			fprintf(logfile, "ת��IP���ݰ�\n");
		}

		// ��ԴIP��ַ�������ֽ���ת��Ϊ���ʮ���ƣ�����ӡ
		in_addr addr;
		addr.s_addr = t->IPHeader.SrcIP;
		char* temp = inet_ntoa(addr);
		fprintf(logfile, "ԴIP��");
		fprintf(logfile, "%s\t", temp);

		// ��ӡĿ��IP��ַ
		fprintf(logfile, "Ŀ��IP��");
		addr.s_addr = t->IPHeader.DstIP;
		temp = inet_ntoa(addr);
		fprintf(logfile, "%s\t", temp);

		// ��ӡԴMAC��ַ
		fprintf(logfile, "ԴMAC��");
		for (int i = 0; i < 6; i++)
			fprintf(logfile, "%02x:", t->FrameHeader.SrcMAC[i]);
		fprintf(logfile, "\t");

		// ��ӡĿ��MAC��ַ
		fprintf(logfile, "Ŀ��MAC��");
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
//���߳�
HANDLE hThread;
DWORD dwThreadId;
int choose_dev;
//int log_print::num = 0;
//log_print log_print::diary[50] = {};
FILE* log_print::logfile = nullptr;
log_print mylog;
BYTE broadcast[6] = { 0xff,0xff,0xff,0xff,0xff,0xff };



#pragma pack(1)
class RouterItem//·�ɱ����
{
public:
	DWORD mask;//����
	DWORD net;//Ŀ������
	DWORD nextip;//��һ��
	BYTE nextmac[6];
	int index;//�ڼ���
	int type;//0Ϊֱ�����ӣ�1Ϊ�û����
	RouterItem* nextitem;//����������ʽ�洢
	RouterItem()
	{
		memset(this, 0, sizeof(*this));//ȫ����ʼ��Ϊ0
	}
	void PrintItem()//��ӡ�������ݣ����롢Ŀ�����硢��һ��IP������
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
class RouterTable//·�ɱ�
{
public:
	RouterItem* head, * tail;
	int num;//����
	RouterTable()//��ʼ�������ֱ������������
	{
		head = new RouterItem;
		tail = new RouterItem;
		head->nextitem = tail;
		num = 0;
		for (int i = 0; i < 2; i++)
		{
			RouterItem* temp = new RouterItem;
			temp->net = (inet_addr(my_IP[i])) & (inet_addr(mask[i]));//����������ip��������а�λ�뼴Ϊ��������
			temp->mask = inet_addr(mask[i]);
			temp->type = 0;//0��ʾֱ�����ӣ�����ɾ��
			this->Add_ritem(temp);
		}
	}


	// ·�ɱ����Ӻ���
	void Add_ritem(RouterItem* a)
	{
		RouterItem* pointer;

		// ���a��typeΪ0����ʾ��Ҫ���뵽����ͷ��
		if (!a->type)
		{
			// ��a���뵽����ͷ��
			a->nextitem = head->nextitem;
			head->nextitem = a;
			a->type = 0;
		}
		else // ���������ɳ������ҵ����ʵ�λ��
		{
			for (pointer = head->nextitem; pointer != tail && pointer->nextitem != tail; pointer = pointer->nextitem)
			{
				// �ҵ������a����������������һ�������С��λ��
				if (a->mask < pointer->mask && a->mask >= pointer->nextitem->mask || pointer->nextitem == tail)
				{
					break;
				}
			}
			// ��a���뵽�ҵ���λ��
			a->nextitem = pointer->nextitem;
			pointer->nextitem = a;
		}

		// ��������ÿ���ڵ��index
		RouterItem* p = head->nextitem;
		for (int i = 0; p != tail; p = p->nextitem, i++)
		{
			p->index = i;
		}

		// ����·�ɱ��е���Ŀ����
		num++;
	}



	// ·�ɱ��ɾ������
	void Delate_ritem(int index)
	{
		// ѭ����������
		for (RouterItem* t = head; t->nextitem != tail; t = t->nextitem)
		{
			// ���������ÿ���ڵ��index�Ƿ���ڴ����index
			if (t->nextitem->index == index)
			{
				// ����ҵ�ƥ���index
				if (t->nextitem->type == 0)
				{
					// ��������typeΪ0����ʾ����ɾ���������ʾ��Ϣ������
					printf("�����ɾ��\n");
					return;
				}
				else
				{
					// ���򣬴�������ɾ������
					t->nextitem = t->nextitem->nextitem;
					return;
				}
			}
		}

		// ���ѭ����������δ�ҵ�ƥ���index�������ʾ��Ϣ
		printf("�޸ñ���\n");
	}


	void print()
	{
		for (RouterItem* p = head->nextitem; p != tail; p = p->nextitem)
		{
			p->PrintItem();
		}
	}

	// �����ǰ׺��������һ����IP��ַ
	DWORD RouterFind(DWORD ip)
	{
		// ѭ������·�ɱ���ͷ�ڵ����һ���ڵ㿪ʼ��ֱ��β�ڵ�
		for (RouterItem* t = head->nextitem; t != tail; t = t->nextitem)
		{
			// ��鴫���IP��ַ�Ƿ�ƥ�䵱ǰ·�ɱ�������粿��
			if ((t->mask & ip) == t->net)
			{
				// ���ƥ�䣬���ظ�·�ɱ������һ��IP��ַ
				return t->nextip;
			}
		}

		// ���ѭ����������δ�ҵ�ƥ��������-1��ʾδ�ҵ�
		return -1;
	}

};
#pragma pack()


//��ȡ�����豸��IP��ַ��MAC��ַӳ��
void ARP_operation(DWORD ip0, BYTE mac[])
{
	ARP_Header ARP_datagram;
	//��APRFrame.FrameHeader.DesMAC����Ϊ�㲥��ַ
	for (int i = 0; i < 6; i++)
		ARP_datagram.FrameHeader.DesMAC[i] = 0xff;
	//��APRFrame.FrameHeader.SrcMAC����Ϊ����������MAC��ַ
	for (int i = 0; i < 6; i++)
	{
		ARP_datagram.FrameHeader.SrcMAC[i] = my_MAC[i];
		ARP_datagram.SendHa[i] = my_MAC[i];
	}
	ARP_datagram.FrameHeader.FrameType = htons(0x0806);//֡����ΪARP
	ARP_datagram.HardwareType = htons(0x0001);//Ӳ������Ϊ��̫��
	ARP_datagram.ProtocolType = htons(0x0800);//Э������ΪIP
	ARP_datagram.HLen = 6;//Ӳ����ַ����Ϊ6
	ARP_datagram.PLen = 4;//Э���ַ��Ϊ4
	ARP_datagram.Operation = htons(0x0001);//����ΪARP����
	//��ARP_datagram.SendIP����Ϊ���������ϰ󶨵�IP��ַ
	ARP_datagram.SendIP = inet_addr(my_IP[0]);
	//��ARP_datagram.RecvHa����Ϊ0
	for (int i = 0; i < 6; i++)
	{
		ARP_datagram.RecvHa[i] = 0;
	}
	//��ARP_datagram.RecvIP����Ϊ�����IP��ַ
	ARP_datagram.RecvIP = ip0;
	memset(mac, 0, sizeof(mac));

	//����ARP���ݰ�
	int send_ARP_succeed = pcap_sendpacket(adhandle, (u_char*)&ARP_datagram, sizeof(ARP_Header));
		if (send_ARP_succeed != 0)
		{
			printf("���ʹ���\n");
			return;
		}
		else
		{
			while (1)//ѭ���������ݰ�
			{
				pcap_pkthdr* arp_header;
				const u_char* arp_data;
				int recv_succeed = pcap_next_ex(adhandle, &arp_header, &arp_data);
				if (recv_succeed == 1)
				{
					ARP_Header* arpPacket = (ARP_Header*)arp_data;

					//֡����Ϊ ARP Э������,������Ϊ ARP �ظ�
					if (ntohs(arpPacket->FrameHeader.FrameType) == 0x0806 && ntohs(arpPacket->Operation) == 0x0002)
					{//���Ŀ��MAC��ַ
							mylog.ARP_print(arpPacket);
							//����հ���ԴMAC��ַ
							for (int i = 0; i < 6; i++)
								mac[i] = arpPacket->FrameHeader.SrcMAC[i];
							break;
						
					}
				}
			}
		}
}




#pragma pack(1)
class ArpTable//ARP����IP��MAC�Ķ�Ӧ��ϵ�洢��һ�ű��
{
public:
	DWORD ip;
	BYTE mac[6];
	static int num;

	//�����Լ���ARP����
	static void Insert_my_Arp(DWORD ip, BYTE mac[6])
	{
		arptable[num].ip = ip;
		memcpy(arptable[num].mac, mac, 6);
		num++;
	}


	//����������ARP����
	static void Insert_other_Arp(DWORD ip, BYTE mac[6])
	{
		arptable[num].ip = ip;
		ARP_operation(ip, arptable[num].mac);//�ҵ���Ӧ��MAC��ַ
		memcpy(mac, arptable[num].mac, 6);
		num++;
	}


	// ����ARP�����Ƿ����ָ��IP����������򽫶�Ӧ��MAC��ַ���Ƶ�����mac��
	static int FindArp(DWORD ip, BYTE mac[6])
	{
		// ��ʼ��mac����Ϊ0
		memset(mac, 0, 6);

		// ѭ������ARP���е�ÿһ��
		for (int i = 0; i < num; i++)
		{
			// ��鵱ǰARP�����IP�Ƿ��봫���IP��ƥ��
			if (ip == arptable[i].ip)
			{
				// ���ƥ�䣬����ARP�����MAC��ַ���Ƶ�����mac��
				memcpy(mac, arptable[i].mac, 6);

				// ����1��ʾ�ҵ���ƥ���ARP����
				return 1;
			}
		}

		// ���ѭ����������δ�ҵ�ƥ��������0��ʾδ�ҵ�
		return 0;
	}



	// ��ӡARP��
	static void PrintArpTable() {
		// �����ʾ��Ϣ
		printf("ARP Table:\n");

		// ѭ������ARP���е�ÿһ��
		for (int i = 0; i < num; i++) {
			// ʹ�� inet_ntoa �� DWORD ���͵� IP ��ַת��Ϊ�ַ�����ʽ
			in_addr addr;
			addr.s_addr = arptable[i].ip;
			char* ipStr = inet_ntoa(addr);

			// ��ӡ��ǰARP�����IP��ַ
			printf("IP: %s\tMAC: ", ipStr);

			// ѭ��������ǰARP�����MAC��ַ
			for (int j = 0; j < 6; j++) {
				// ��ӡMAC��ַ��ÿһ�ֽڣ���ʮ�����Ʊ�ʾ�������ֽ�֮�����ð��
				printf("%02X", static_cast<int>(arptable[i].mac[j]));
				if (j < 5) printf(":");
			}

			// ���У���ʾ��ǰARP�����ӡ���
			printf("\n");
		}
	}



}arptable[50];
#pragma pack()

int ArpTable::num = 0;
