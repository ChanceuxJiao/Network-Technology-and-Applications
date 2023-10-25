#include<iostream>
#include"pcap.h"
#include<iomanip>
#include<WS2tcpip.h>
#include<windows.h>
#include<cstdlib>
#pragma comment(lib,"wpcap.lib")
#pragma comment(lib,"packet.lib")
#pragma comment(lib,"wsock32.lib")
#pragma comment(lib,"ws2_32.lib")
#define LINE_LEN 16
#define MAX_ADDR_LEN 16
using namespace std;

#pragma pack(1)		//�����ֽڶ��뷽ʽ
typedef struct FrameHeader_t {	//֡�ײ�
	BYTE	DesMAC[6];	// Ŀ�ĵ�ַ
	BYTE 	SrcMAC[6];	// Դ��ַ
	WORD	FrameType;	// ֡����
} FrameHeader_t;
typedef struct IPHeader_t {		//IP�ײ�
	BYTE Ver_HLen;              //IPЭ��汾��IP�ײ����ȡ���4λΪ�汾����4λΪ�ײ��ĳ���(��λΪ4bytes)
	BYTE TOS;                   //��������
	WORD TotalLen;              //�ܳ���
	WORD ID;                    //��ʶ
	WORD Flag_Segment;          //��־ Ƭƫ��
	BYTE TTL;                   //��������
	BYTE Protocol;              //Э��
	WORD Checksum;              //ͷ��У���
	u_int SrcIP;                //ԴIP
	u_int DstIP;                //Ŀ��IP
} IPHeader_t;
typedef struct Data_t {	//����֡�ײ���IP�ײ������ݰ�
	FrameHeader_t	FrameHeader;
	IPHeader_t		IPHeader;
} Data_t;
#pragma pack()	//�ָ�ȱʡ���뷽ʽ

//��IP���ݰ�����������ӡ�����Ϣ��IP����������ԭ������֡��14�ֽڿ�ʼ������ȡ����Ӧ���ֶΡ�
void ip_protocol_packet_handle(const struct pcap_pkthdr* pkt_header, const u_char* pkt_data)
{
	IPHeader_t* IPHeader;                   // ����ָ��IP���ݰ��ײ���ָ��
	IPHeader = (IPHeader_t*)(pkt_data + 14);// ����IP���ݰ��ײ���λ�ã�ƫ��14�ֽڣ�������ָ��ָ���λ��

	// ��ȡ��־��Ƭƫ����Ϣ
	uint16_t flags_segment = ntohs(IPHeader->Flag_Segment);
	uint16_t fragment_offset = flags_segment & 0x1FFF;

	// �������ڴ洢Դ��Ŀ�ĵ�ַ���׽��ֽṹ
	sockaddr_in source, dest;
	char sourceIP[MAX_ADDR_LEN], destIP[MAX_ADDR_LEN];
	char str[16];

	// ��IP���ݰ��ײ���ȡԴ��ַ��Ŀ�ĵ�ַ
	source.sin_addr.s_addr = IPHeader->SrcIP;
	dest.sin_addr.s_addr = IPHeader->DstIP;

	// ����ȡ�ĵ�ַ��Ϣת��Ϊ�ɶ����ַ�����ʽ
	strncpy_s(sourceIP, inet_ntop(AF_INET, &source.sin_addr, str, 16), MAX_ADDR_LEN);
	strncpy_s(destIP, inet_ntop(AF_INET, &dest.sin_addr, str, 16), MAX_ADDR_LEN);


	//��ʼ���
	cout << dec << "Version��" << (int)(IPHeader->Ver_HLen >> 4) << endl;
	cout << "Header Length��";
	cout << (int)((IPHeader->Ver_HLen & 0x0f) * 4) << " Bytes" << endl;
	cout << "Tos��" << (int)IPHeader->TOS << endl;
	cout << "Total Length��" << (int)ntohs(IPHeader->TotalLen) << endl;
	cout << "Identification��0x" << hex << setw(4) << setfill('0') << ntohs(IPHeader->ID) << endl;
	cout << "Ƭƫ�ƣ�\t" << fragment_offset * 8 << " Bytes" << endl;
	cout <<dec<< "Time to live��" << (int)IPHeader->TTL << endl;
	cout << "Protocol Type�� ";
	switch (IPHeader->Protocol)
	{
	case 1:
		cout << "ICMP";
		break;
	case 2:
		cout << "IGMP";
		break;
	case 6:
		cout << "TCP";
		break;
	case 17:
		cout << "UDP";
		break;
	default:
		break;
	}
	cout << "(" << (int)IPHeader->Protocol << ")" << endl;
	cout << "Header checkSum��0x" << hex << setw(4) << setfill('0') << ntohs(IPHeader->Checksum) << endl;//ͷ��У���
	cout << "Source��" << sourceIP << endl;
	cout << "Destination��" << destIP << endl;

}

//��̫��֡֡����������ӡ�����Ϣ
void ethernet_protocol_packet_handle(u_char* param, const struct pcap_pkthdr* pkt_header, const u_char* pkt_data)
{
	FrameHeader_t* ethernet_protocol;//��̫��Э��
	u_short ethernet_type;			//��̫������
	u_char* mac_string;				//��̫����ַ

	static int count = 1;//��¼��������ݰ�������

	//��ȡ��̫����������
	ethernet_protocol = (FrameHeader_t*)pkt_data;//���һ̫��Э����������
	ethernet_type = ntohs(ethernet_protocol->FrameType);//�����̫������

	cout <<endl<< "\t�� " << count << " ��IP���ݰ�������" << endl;
	cout << "==============Ethernet Protocol=================" << endl;
	count++;

	//��̫��Ŀ���ַ
	mac_string = ethernet_protocol->DesMAC;

	cout << "Destination Mac Address�� ";
	cout << hex << setw(2) << setfill('0') << (u_int)mac_string[0] << ":";
	cout << hex << setw(2) << setfill('0') << (u_int)mac_string[1] << ":";
	cout << hex << setw(2) << setfill('0') << (u_int)mac_string[2] << ":";
	cout << hex << setw(2) << setfill('0') << (u_int)mac_string[3] << ":";
	cout << hex << setw(2) << setfill('0') << (u_int)mac_string[4] << ":";
	cout << hex << setw(2) << setfill('0') << (u_int)mac_string[5] << endl;

	//��̫��Դ��ַ
	mac_string = ethernet_protocol->SrcMAC;

	cout << "Source Mac Address�� ";
	cout << hex << setw(2) << setfill('0') << (u_int)mac_string[0] << ":";
	cout << hex << setw(2) << setfill('0') << (u_int)mac_string[1] << ":";
	cout << hex << setw(2) << setfill('0') << (u_int)mac_string[2] << ":";
	cout << hex << setw(2) << setfill('0') << (u_int)mac_string[3] << ":";
	cout << hex << setw(2) << setfill('0') << (u_int)mac_string[4] << ":";
	cout << hex << setw(2) << setfill('0') << (u_int)mac_string[5] << endl;

	cout << "Ethernet type�� ";
	cout << " 0x" << setw(4) << setfill('0') << ethernet_type << endl;
	cout << "�����Э�飺 ";
	switch (ethernet_type)
	{
	case 0x0800:
		cout << "IPЭ��";
		break;
	case 0x0806:
		cout << "ARPЭ��";
		break;
	case 0x0835:
		cout << "RARPЭ��";
		break;
	default:
		cout << "����Э��";
		break;
	}
	

	//����IPHeader������
	if (ethernet_type == 0x0800)
	{
		cout <<endl<< "==============IP Protocol=================" << endl;
		ip_protocol_packet_handle(pkt_header, pkt_data);
	}
}


int main() {
	//�����ӿں�IP��ַ�Ļ�ȡ
	pcap_if_t* alldevs; 	               //ָ���豸�����ײ���ָ��
	pcap_if_t* d;                           // ���ڱ�������ӿ��б�
	    
	int i = 0;                              // ����ѡ��Ҫ����������ӿڵı��
	int inum = 0;                            // ѡ��ǰ������ӿڱ��
	pcap_t* adhandle;                       // ���ڲ������ݰ�
	char errbuf[PCAP_ERRBUF_SIZE];	//������Ϣ������
	
	//��ñ�������ӿ�
	if (pcap_findalldevs_ex(PCAP_SRC_IF_STRING, NULL, &alldevs, errbuf) == -1)
	{
		//������
		cout << "�޷���ȡ�����豸��" << errbuf << endl;
		pcap_freealldevs(alldevs);
		return 0;
	}

	for (d = alldevs; d != NULL; d = d->next) //��ʾ�ӿ��б�
	{
		cout << dec << ++i << ": " << d->name; //����d->name��ȡ������ӿ��豸������
		if (d->description) { //����d->description��ȡ������ӿ��豸��������Ϣ
			cout << d->description << endl;
		}
		else {
			cout << "�����������Ϣ" << endl;
			return -1;
		}
	}
	if (i == 0)
	{
		cout << "wrong!" << endl;
		return -1;
	}

	cout << "������Ҫ�򿪵����ںţ�1-" << i << "����";
	cin >> inum;

	//����û��Ƿ�ָ������Ч���豸
	if (inum < 1 || inum > i)
	{
		cout << "����������������Χ" << endl;

		pcap_freealldevs(alldevs);
		return -1;
	}

	//��ת��ѡ���ı��ؽӿ�
	for (d = alldevs, i = 0; i < inum - 1; d = d->next, i++);


	//������ӿ�
	if ((adhandle = pcap_open(d->name, 65536, PCAP_OPENFLAG_PROMISCUOUS, 1000, NULL, errbuf)) == NULL)
	{
		cout << "�޷����豸!" << endl;
		pcap_freealldevs(alldevs);
		return -1;
	}


	cout << "������" << d->description << endl;
	pcap_freealldevs(alldevs);
	int cnt = -1;
	cout << "��Ҫ�������ݰ��ĸ�����";
	cin >> cnt;
	pcap_loop(adhandle, cnt, ethernet_protocol_packet_handle, NULL);
	pcap_close(adhandle);//�ر�����ӿ�

	system("pause");
	return 0;
}
