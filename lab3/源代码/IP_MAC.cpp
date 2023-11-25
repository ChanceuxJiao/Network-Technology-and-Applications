#include <Winsock2.h>
#include<Windows.h>
#include<iostream>
#include <ws2tcpip.h>
#include "pcap.h"
#include "stdio.h"
#include<time.h>
#include <string>

#pragma comment(lib, "Packet.lib")
#pragma comment(lib,"wpcap.lib")
#pragma comment(lib,"ws2_32.lib")//表示链接的时侯找ws2_32.lib
#pragma warning( disable : 4996 )//要使用旧函数
#define _WINSOCK_DEPRECATED_NO_WARNINGS
using namespace std;

// 存储错误信息的缓冲区
char errbuf[PCAP_ERRBUF_SIZE];


#pragma pack(1)//按字节对齐
struct FrameHeader_t //帧首部
{
	BYTE DesMAC[6];  //目的地址
	BYTE SrcMAC[6];  //源地址
	WORD FrameType;  //帧类型
};

struct ARPFrame_t // ARP帧
{
	FrameHeader_t FrameHeader;  // 帧首部结构体对象
	WORD HardwareType;          // 硬件类型
	WORD ProtocolType;          // 协议类型
	BYTE HLen;                  // 硬件地址长度
	BYTE PLen;                  // 协议地址长度
	WORD Operation;             // 操作类型
	BYTE SendHa[6];             // 发送方硬件地址
	DWORD sendIP;               // 发送方协议地址
	BYTE RecvHa[6];             // 接收方硬件地址
	DWORD RecvIP;               // 接收方协议地址
};
#pragma pack() // 恢复缺省对齐方式



//打印MAC地址
void print_MAC_addr(BYTE MAC[6])
{
	// 循环遍历 MAC 地址的每个字节
	for (int i = 0; i < 6; i++)
	{
		// 打印每个字节的十六进制表示
		if (i < 5)
			printf("%02x:", MAC[i]);
		else
			printf("%02x", MAC[i]);
	}

};

//打印IP地址
void print_IP_addr(DWORD IP)
{
	// 将 DWORD 类型的 IP 地址转换为 BYTE 指针
	BYTE* ip = (BYTE*)&IP;
	for (int i = 0; i < 4; i++)
	{
		// 打印每个字节的十进制表示
		if (i < 3)
		{
			cout << dec << (int)*ip << ".";
		}
		else
		{
			cout << dec << (int)*ip;
		}
		ip++;
	}
};





//捕获与ARP请求对应的响应，打印与IP匹配的MAC地址
void capture_response(ARPFrame_t*& IPPacket, pcap_t* pcap_handle, struct pcap_pkthdr* pkt_header, const u_char* pkt_data, DWORD sendIP, DWORD recvIP)
{
	while (true)
	{
		int retn_inum = pcap_next_ex(pcap_handle, &pkt_header, &pkt_data);

		if (retn_inum == 0)
		{
			// 没有捕获到数据包
			cout << "  没有捕获到数据报" << endl;
		}
		else if (retn_inum == -1)
		{
			// 捕获数据包时发生错误
			cout << "  捕获数据包时发生错误：" << errbuf << endl;
			return;
		}
		else
		{
			// 成功捕获到一个数据包
			IPPacket = (ARPFrame_t*)pkt_data;

			if (IPPacket->RecvIP == sendIP && IPPacket->sendIP == recvIP)
			{
				// 捕获到与发送的ARP请求对应的ARP响应
				cout << "IP地址：";
				print_IP_addr(IPPacket->sendIP);
				cout << endl;
				cout << "MAC地址：";
				print_MAC_addr(IPPacket->SendHa);
				cout << endl;
				break;
			}
		}
	}
	return;
}



int main()
{
	// sendIP 和 recvIP 是 DWORD 类型的变量，可能用于存储发送和接收的IP地址
	DWORD sendIP;
	DWORD recvIP;

	pcap_if_t* alldevs;      // 指向设备列表首部的指针
	pcap_if_t* d;            // 用于遍历网络接口列表
	pcap_addr_t* devs_addr;  
	
	int i = 0;               // 用于选择要监听的网络接口的编号
	int inum;                // 选择当前的网络接口编号


	// ARPFrame_t 是一个结构体类型，用于表示ARP帧的结构
	ARPFrame_t ARPFrame;

	// IPPacket 是一个指向 ARPFrame_t 结构体的指针,用于捕获数据包
	ARPFrame_t* IPPacket=nullptr;

	// pcap_pkthdr 结构体表示捕获的数据包的头信息
	struct pcap_pkthdr* pkt_header=nullptr;

	// 指向捕获的数据包的数据部分的指针
	const u_char* pkt_data=nullptr;



	//获得本机网络接口
	if (pcap_findalldevs_ex(PCAP_SRC_IF_STRING, NULL, &alldevs, errbuf) == -1)
	{
		//错误处理
		cout << "无法获取本机设备！" << errbuf << endl;
		pcap_freealldevs(alldevs);
		return 0;
	}

	//显示接口列表
	cout << "本地网络接口："<<endl ;
	for (d = alldevs; d != NULL; d = d->next)
	{
		cout << endl;
		cout << "****************网卡" << i + 1 <<"******************" << endl << "名称：" << d->name << endl;
		cout << "描述信息：" << d->description << endl;

		for (devs_addr = d->addresses; devs_addr != NULL; devs_addr = devs_addr->next)
		{
			if (devs_addr->addr->sa_family == AF_INET)
			{
				cout << "IP地址：" << inet_ntoa(((struct sockaddr_in*)(devs_addr->addr))->sin_addr) << endl;
				cout << "子网掩码：" << inet_ntoa(((struct sockaddr_in*)(devs_addr->netmask))->sin_addr) << endl;
				cout << "广播地址：" << inet_ntoa(((struct sockaddr_in*)(devs_addr->broadaddr))->sin_addr) << endl;
			}
		}
		i++;
	}


	cout << endl;
	cout << "请选要打开的网卡号：";
	cin >> inum;

	//检查用户是否指定了有效的设备
	if (inum < 1 || inum > i)
	{
		cout << "适配器数量超出范围" << endl;

		pcap_freealldevs(alldevs);
		return -1;
	}

	d = alldevs;
	for (int i = 1; i < inum; i++)
	{
		d = d->next;
	}

	pcap_t* pcap_handle = pcap_open(d->name,65536 , PCAP_OPENFLAG_PROMISCUOUS, 1000, NULL, errbuf);//打开网卡
	if (pcap_handle == NULL)
	{
		cout << "打开网卡时发生错误：" << errbuf << endl;
		return 0;
	}
	else
	{
		cout <<inum<< "号网卡已成功打开" << endl;
	}
	//帧类型为ARP
	ARPFrame.FrameHeader.FrameType = htons(0x0806);
	//硬件类型为以太网
	ARPFrame.HardwareType = htons(0x0001);
	//协议类型为IP
	ARPFrame.ProtocolType = htons(0x0800);

	for (int i = 0; i < 6; i++)
	{
		ARPFrame.FrameHeader.DesMAC[i] = 0xFF;//设置为本机广播地址
		ARPFrame.FrameHeader.SrcMAC[i] = 0x88;//设置为虚拟的MAC地址
		ARPFrame.RecvHa[i] = 0;//接收方硬件地址设置为0
		ARPFrame.SendHa[i] = 0x88;//发送方硬件地址
	}
	ARPFrame.HLen = 6;//硬件地址长度为6
	ARPFrame.PLen = 4; // 协议地址长为4
	ARPFrame.Operation = htons(0x0001);//操作为ARP请求
	sendIP = ARPFrame.sendIP = htonl(0x60606060);//源IP地址设置为虚拟的IP地址 


	//将所选择的网卡的IP设置为请求的IP地址
	for (devs_addr = d->addresses; devs_addr != NULL; devs_addr = devs_addr->next)
	{
		if (devs_addr->addr->sa_family == AF_INET)
		{
			recvIP = ARPFrame.RecvIP = inet_addr(inet_ntoa(((struct sockaddr_in*)(devs_addr->addr))->sin_addr));
		}
	}

	// 发送ARP请求帧，以获得本机的MAC
	if (pcap_sendpacket(pcap_handle, (u_char*)&ARPFrame, sizeof(ARPFrame_t)) != 0)
	{
		// 如果发送数据包失败，释放资源并抛出异常（throw -7）
		pcap_freealldevs(alldevs);
		throw - 7;
	}
	else
	{
		cout << "发送ARP请求并捕获响应：" << endl;
		capture_response(IPPacket, pcap_handle, pkt_header, pkt_data, sendIP, recvIP);//捕获响应数据包，解析获得MAC地址	
	}

	cout << endl;
	cout << "请输入IP地址:";
	char str[15];
	cin >> str;

	// 将输入的IP地址转换为DWORD类型，同时设置为ARP请求帧的目标IP地址
	recvIP = ARPFrame.RecvIP = inet_addr(str);

	// 将ARP请求帧的源IP地址设置为之前捕获到的ARP响应的源IP地址
	sendIP = ARPFrame.sendIP = IPPacket->sendIP;

	// 将ARP请求帧的源MAC地址设置为之前捕获到的ARP响应的源MAC地址
	for (int i = 0; i < 6; i++)
	{
		ARPFrame.SendHa[i] = ARPFrame.FrameHeader.SrcMAC[i] = IPPacket->SendHa[i];
	}

	// 发送ARP请求帧，以获得指定IP的MAC
	if (pcap_sendpacket(pcap_handle, (u_char*)&ARPFrame, sizeof(ARPFrame_t)) != 0)
	{
		cout << "发送ARP请求并捕获响应：" << endl;
	}
	else
	{
		cout << "ARP请求发送成功" << endl;
		capture_response(IPPacket,pcap_handle, pkt_header, pkt_data, sendIP, recvIP);//捕获响应数据包，解析获得MAC地址
	}
}
