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

#pragma pack(1)		//进入字节对齐方式
typedef struct FrameHeader_t {	//帧首部
	BYTE	DesMAC[6];	// 目的地址
	BYTE 	SrcMAC[6];	// 源地址
	WORD	FrameType;	// 帧类型
} FrameHeader_t;
typedef struct IPHeader_t {		//IP首部
	BYTE Ver_HLen;              //IP协议版本和IP首部长度。高4位为版本，低4位为首部的长度(单位为4bytes)
	BYTE TOS;                   //服务类型
	WORD TotalLen;              //总长度
	WORD ID;                    //标识
	WORD Flag_Segment;          //标志 片偏移
	BYTE TTL;                   //生存周期
	BYTE Protocol;              //协议
	WORD Checksum;              //头部校验和
	u_int SrcIP;                //源IP
	u_int DstIP;                //目的IP
} IPHeader_t;
typedef struct Data_t {	//包含帧首部和IP首部的数据包
	FrameHeader_t	FrameHeader;
	IPHeader_t		IPHeader;
} Data_t;
#pragma pack()	//恢复缺省对齐方式

//对IP数据包作分析并打印相关信息，IP包的内容在原有物理帧后14字节开始。并提取出相应的字段。
void ip_protocol_packet_handle(const struct pcap_pkthdr* pkt_header, const u_char* pkt_data)
{
	IPHeader_t* IPHeader;                   // 创建指向IP数据包首部的指针
	IPHeader = (IPHeader_t*)(pkt_data + 14);// 计算IP数据包首部的位置（偏移14字节），并将指针指向该位置

	// 提取标志和片偏移信息
	uint16_t flags_segment = ntohs(IPHeader->Flag_Segment);
	uint16_t fragment_offset = flags_segment & 0x1FFF;

	// 创建用于存储源和目的地址的套接字结构
	sockaddr_in source, dest;
	char sourceIP[MAX_ADDR_LEN], destIP[MAX_ADDR_LEN];
	char str[16];

	// 从IP数据包首部提取源地址和目的地址
	source.sin_addr.s_addr = IPHeader->SrcIP;
	dest.sin_addr.s_addr = IPHeader->DstIP;

	// 将提取的地址信息转换为可读的字符串形式
	strncpy_s(sourceIP, inet_ntop(AF_INET, &source.sin_addr, str, 16), MAX_ADDR_LEN);
	strncpy_s(destIP, inet_ntop(AF_INET, &dest.sin_addr, str, 16), MAX_ADDR_LEN);


	//开始输出
	cout << dec << "Version：" << (int)(IPHeader->Ver_HLen >> 4) << endl;
	cout << "Header Length：";
	cout << (int)((IPHeader->Ver_HLen & 0x0f) * 4) << " Bytes" << endl;
	cout << "Tos：" << (int)IPHeader->TOS << endl;
	cout << "Total Length：" << (int)ntohs(IPHeader->TotalLen) << endl;
	cout << "Identification：0x" << hex << setw(4) << setfill('0') << ntohs(IPHeader->ID) << endl;
	cout << "片偏移：\t" << fragment_offset * 8 << " Bytes" << endl;
	cout <<dec<< "Time to live：" << (int)IPHeader->TTL << endl;
	cout << "Protocol Type： ";
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
	cout << "Header checkSum：0x" << hex << setw(4) << setfill('0') << ntohs(IPHeader->Checksum) << endl;//头部校验和
	cout << "Source：" << sourceIP << endl;
	cout << "Destination：" << destIP << endl;

}

//以太网帧帧作分析并打印相关信息
void ethernet_protocol_packet_handle(u_char* param, const struct pcap_pkthdr* pkt_header, const u_char* pkt_data)
{
	FrameHeader_t* ethernet_protocol;//以太网协议
	u_short ethernet_type;			//以太网类型
	u_char* mac_string;				//以太网地址

	static int count = 1;//记录捕获的数据包的数量

	//获取以太网数据内容
	ethernet_protocol = (FrameHeader_t*)pkt_data;//获得一太网协议数据内容
	ethernet_type = ntohs(ethernet_protocol->FrameType);//获得以太网类型

	cout <<endl<< "\t第 " << count << " 个IP数据包被捕获" << endl;
	cout << "==============Ethernet Protocol=================" << endl;
	count++;

	//以太网目标地址
	mac_string = ethernet_protocol->DesMAC;

	cout << "Destination Mac Address： ";
	cout << hex << setw(2) << setfill('0') << (u_int)mac_string[0] << ":";
	cout << hex << setw(2) << setfill('0') << (u_int)mac_string[1] << ":";
	cout << hex << setw(2) << setfill('0') << (u_int)mac_string[2] << ":";
	cout << hex << setw(2) << setfill('0') << (u_int)mac_string[3] << ":";
	cout << hex << setw(2) << setfill('0') << (u_int)mac_string[4] << ":";
	cout << hex << setw(2) << setfill('0') << (u_int)mac_string[5] << endl;

	//以太网源地址
	mac_string = ethernet_protocol->SrcMAC;

	cout << "Source Mac Address： ";
	cout << hex << setw(2) << setfill('0') << (u_int)mac_string[0] << ":";
	cout << hex << setw(2) << setfill('0') << (u_int)mac_string[1] << ":";
	cout << hex << setw(2) << setfill('0') << (u_int)mac_string[2] << ":";
	cout << hex << setw(2) << setfill('0') << (u_int)mac_string[3] << ":";
	cout << hex << setw(2) << setfill('0') << (u_int)mac_string[4] << ":";
	cout << hex << setw(2) << setfill('0') << (u_int)mac_string[5] << endl;

	cout << "Ethernet type： ";
	cout << " 0x" << setw(4) << setfill('0') << ethernet_type << endl;
	cout << "网络层协议： ";
	switch (ethernet_type)
	{
	case 0x0800:
		cout << "IP协议";
		break;
	case 0x0806:
		cout << "ARP协议";
		break;
	case 0x0835:
		cout << "RARP协议";
		break;
	default:
		cout << "其他协议";
		break;
	}
	

	//进入IPHeader处理函数
	if (ethernet_type == 0x0800)
	{
		cout <<endl<< "==============IP Protocol=================" << endl;
		ip_protocol_packet_handle(pkt_header, pkt_data);
	}
}


int main() {
	//本机接口和IP地址的获取
	pcap_if_t* alldevs; 	               //指向设备链表首部的指针
	pcap_if_t* d;                           // 用于遍历网络接口列表
	    
	int i = 0;                              // 用于选择要监听的网络接口的编号
	int inum = 0;                            // 选择当前的网络接口编号
	pcap_t* adhandle;                       // 用于捕获数据包
	char errbuf[PCAP_ERRBUF_SIZE];	//错误信息缓冲区
	
	//获得本机网络接口
	if (pcap_findalldevs_ex(PCAP_SRC_IF_STRING, NULL, &alldevs, errbuf) == -1)
	{
		//错误处理
		cout << "无法获取本机设备！" << errbuf << endl;
		pcap_freealldevs(alldevs);
		return 0;
	}

	for (d = alldevs; d != NULL; d = d->next) //显示接口列表
	{
		cout << dec << ++i << ": " << d->name; //利用d->name获取该网络接口设备的名字
		if (d->description) { //利用d->description获取该网络接口设备的描述信息
			cout << d->description << endl;
		}
		else {
			cout << "无相关描述信息" << endl;
			return -1;
		}
	}
	if (i == 0)
	{
		cout << "wrong!" << endl;
		return -1;
	}

	cout << "请输入要打开的网口号（1-" << i << "）：";
	cin >> inum;

	//检查用户是否指定了有效的设备
	if (inum < 1 || inum > i)
	{
		cout << "适配器数量超出范围" << endl;

		pcap_freealldevs(alldevs);
		return -1;
	}

	//跳转到选定的本地接口
	for (d = alldevs, i = 0; i < inum - 1; d = d->next, i++);


	//打开网络接口
	if ((adhandle = pcap_open(d->name, 65536, PCAP_OPENFLAG_PROMISCUOUS, 1000, NULL, errbuf)) == NULL)
	{
		cout << "无法打开设备!" << endl;
		pcap_freealldevs(alldevs);
		return -1;
	}


	cout << "监听：" << d->description << endl;
	pcap_freealldevs(alldevs);
	int cnt = -1;
	cout << "将要捕获数据包的个数：";
	cin >> cnt;
	pcap_loop(adhandle, cnt, ethernet_protocol_packet_handle, NULL);
	pcap_close(adhandle);//关闭网络接口

	system("pause");
	return 0;
}
