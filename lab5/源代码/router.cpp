#pragma warning(disable : 4996)
#include "pcap.h"
#include "router.h"//日志

//using namespace std;


// 函数用于计算并设置IP头部的校验和
void calculate_checkSum(Datagram* temp)
{
	// 将IP头部的校验和字段初始化为0
	temp->IPHeader.Checksum = 0;

	// 用于存储校验和的变量，初始化为0
	unsigned int sum = 0;

	// 将IP头部结构体强制转换为WORD类型数组，每16位为一组
	WORD* t = (WORD*)&temp->IPHeader;

	// 循环遍历每一组16位，计算累加和
	for (int i = 0; i < sizeof(IP_Header) / 2; i++)
	{
		sum += t[i];

		// 如果累加和溢出，则进行回卷
		while (sum >= 0x10000)
		{
			int s = sum >> 16;
			sum -= 0x10000;
			sum += s;
		}
	}

	// 将计算得到的累加和按位取反，并设置为IP头部的校验和
	temp->IPHeader.Checksum = ~sum;
}


// 函数用于检查IP头部的校验和是否有效
bool verify_checkSum(Datagram* temp)
{
	// 用于存储校验和的变量，初始化为0
	unsigned int sum = 0;

	// 将IP头部结构体强制转换为WORD类型数组，每16位为一组
	WORD* t = (WORD*)&temp->IPHeader;

	// 循环遍历每一组16位，计算累加和
	for (int i = 0; i < sizeof(IP_Header) / 2; i++)
	{
		sum += t[i];

		// 如果累加和溢出，则进行回卷
		while (sum >= 0x10000)
		{
			int s = sum >> 16;
			sum -= 0x10000;
			sum += s;
		}
	}

	// 检查校验和是否为0xFFFF (65535)，如果是则返回 true，表示有效
	if (sum == 65535)
	{
		return true;
	}
	else
	{
		return false;
	}
}


//对比MAC地址是否相同
/*
bool is_my_MAC(BYTE a[6], BYTE b[6])
{
	for (int i = 0; i < 6; i++)
	{
		if (a[i] != b[i])
		{
			return 0;
		}
	}
	return 1;
}
*/

/*
//路由转发线程
DWORD WINAPI Forward_Thread(LPVOID lparam)
{
	RouterTable routertable = *(RouterTable*)(LPVOID)lparam;
	pcap_pkthdr* recv_header;
	const u_char* recv_data;
	while (1)
	{
			int recv_succeed = pcap_next_ex(adhandle, &recv_header, &recv_data);
			if (recv_succeed)//接收到消息
			{
				Frame_Header* header = (Frame_Header*)recv_data;
				if (is_my_MAC(header->DesMAC, my_MAC)&& ntohs(header->FrameType) == 0x0800)//确定是发给自己的数据包而且数据包网络层是IPv4
				{
						Datagram* data_gram = (Datagram*)recv_data;
						mylog.IP_print(0, data_gram);
						DWORD destip = data_gram->IPHeader.DstIP;
						DWORD route_next_ip = routertable.RouterFind(destip);//查找是否有对应表项，得到下一跳IP地址
						if (route_next_ip == -1)
						{
							continue;
						}
						if (verify_checkSum(data_gram))//如果校验和不正确，则直接丢弃不进行处理
						{
							if (data_gram->IPHeader.DstIP != inet_addr(my_IP[0]) && data_gram->IPHeader.DstIP != inet_addr(my_IP[1]))//如果不是发给路由器自己的，那么需要转发
							{
									//ICMP_Datagram报文包含IP数据包报头和其它内容
									ICMP_Datagram_t* data_p = (ICMP_Datagram_t*)recv_data;
									ICMP_Datagram_t data_t = *data_p;
									BYTE next_mac[6];
									if (route_next_ip == 0)//下一跳是0，直接投递
									{
										//如果ARP表中没有所需内容，则需要获取ARP
										if (!ArpTable::FindArp(destip, next_mac))
										{
											ArpTable::Insert_other_Arp(destip, next_mac);
										}
											// 将ICMP数据报转换为Datagram结构体
										Datagram* icmp_datagram = (Datagram*)&data_t;

										// 将帧头的源MAC地址设置为本机MAC地址
										memcpy(icmp_datagram->FrameHeader.SrcMAC, icmp_datagram->FrameHeader.DesMAC, 6);

										// 将帧头的目的MAC地址设置为下一跳MAC地址
										memcpy(icmp_datagram->FrameHeader.DesMAC, next_mac, 6);

										// 减少IP头部的TTL字段，如果小于0则不发送
										icmp_datagram->IPHeader.TTL -= 1;
										if (icmp_datagram->IPHeader.TTL < 0)
										{
											return -1;
										}

										// 重新计算并设置IP头部的校验和
										calculate_checkSum(icmp_datagram);

										// 使用pcap库发送数据包
										int send_succeed = pcap_sendpacket(adhandle, (const u_char*)icmp_datagram, 74);

										// 检查发送是否成功
										if (send_succeed == 0)
										{
											// 如果发送成功，记录日志信息
											mylog.IP_print(1, icmp_datagram);
										}
									}

									else if (route_next_ip != -1)//非直接投递，查找下一条IP的MAC
									{
										if (!ArpTable::FindArp(route_next_ip, next_mac))
										{
											ArpTable::Insert_other_Arp(route_next_ip, next_mac);
										}
											// 将ICMP数据报转换为Datagram结构体
										Datagram* icmp_datagram = (Datagram*)&data_t;

										// 将帧头的源MAC地址设置为本机MAC地址
										memcpy(icmp_datagram->FrameHeader.SrcMAC, icmp_datagram->FrameHeader.DesMAC, 6);

										// 将帧头的目的MAC地址设置为下一跳MAC地址
										memcpy(icmp_datagram->FrameHeader.DesMAC, next_mac, 6);

										// 减少IP头部的TTL字段，如果小于0则不发送
										icmp_datagram->IPHeader.TTL -= 1;
										if (icmp_datagram->IPHeader.TTL < 0)
										{
											return -1;
										}

										// 重新计算并设置IP头部的校验和
										calculate_checkSum(icmp_datagram);

										// 使用pcap库发送数据包
										int send_succeed = pcap_sendpacket(adhandle, (const u_char*)icmp_datagram, 74);

										// 检查发送是否成功
										if (send_succeed == 0)
										{
											// 如果发送成功，记录日志信息
											mylog.IP_print(1, icmp_datagram);
										}

									}
							}
						}
				}

			}
	}
}
*/

//路由转发线程
DWORD Forward(RouterTable routertable)
{
	//RouterTable routertable = *(RouterTable*)(LPVOID)lparam;
	pcap_pkthdr* recv_header;
	const u_char* recv_data;
	while (1)
	{
		int recv_succeed = pcap_next_ex(adhandle, &recv_header, &recv_data);
		if (recv_succeed==1)//接收到消息
		{
			Frame_Header* header = (Frame_Header*)recv_data;
			if (ntohs(header->FrameType) == 0x0800)//数据包网络层是IPv4,IP数据包
			{
				Datagram* data_gram = (Datagram*)recv_data;
				mylog.IP_print(0, data_gram);
				DWORD destip = data_gram->IPHeader.DstIP;
				DWORD route_next_ip = routertable.RouterFind(destip);//查找是否有对应表项，得到下一跳IP地址
				if (route_next_ip == -1)
				{
					continue;
				}
				if (verify_checkSum(data_gram))//如果校验和不正确，则直接丢弃不进行处理
				{
					if (data_gram->IPHeader.DstIP != inet_addr(my_IP[0]) && data_gram->IPHeader.DstIP != inet_addr(my_IP[1]))//如果不是发给路由器自己的，那么需要转发
					{
						//ICMP_Datagram报文包含IP数据包报头和其它内容
						ICMP_Datagram_t* data_p = (ICMP_Datagram_t*)recv_data;
						ICMP_Datagram_t data_t = *data_p;
						BYTE next_mac[6];
						if (route_next_ip == 0)//下一跳是0，直接投递
						{
							//如果ARP表中没有所需内容，则需要获取ARP
							if (!ArpTable::FindArp(destip, next_mac))
							{
								ArpTable::Insert_other_Arp(destip, next_mac);
							}
							// 将ICMP数据报转换为Datagram结构体
							Datagram* icmp_datagram = (Datagram*)&data_t;

							// 将帧头的源MAC地址设置为本机MAC地址
							memcpy(icmp_datagram->FrameHeader.SrcMAC, icmp_datagram->FrameHeader.DesMAC, 6);

							// 将帧头的目的MAC地址设置为下一跳MAC地址
							memcpy(icmp_datagram->FrameHeader.DesMAC, next_mac, 6);

							// 减少IP头部的TTL字段，如果小于0则不发送
							icmp_datagram->IPHeader.TTL -= 1;
							if (icmp_datagram->IPHeader.TTL < 0)
							{
								return -1;
							}

							// 重新计算并设置IP头部的校验和
							calculate_checkSum(icmp_datagram);

							// 使用pcap库发送数据包
							int send_succeed = pcap_sendpacket(adhandle, (const u_char*)icmp_datagram, 74);

							// 检查发送是否成功
							if (send_succeed == 0)
							{
								// 如果发送成功，记录日志信息
								mylog.IP_print(1, icmp_datagram);
							}
						}

						else if (route_next_ip != -1)//非直接投递，查找下一条IP的MAC
						{
							if (!ArpTable::FindArp(route_next_ip, next_mac))
							{							
								//如果ARP表中没有所需内容，则需要获取ARP
								ArpTable::Insert_other_Arp(route_next_ip, next_mac);
							}
							// 将ICMP数据报转换为Datagram结构体
							Datagram* icmp_datagram = (Datagram*)&data_t;

							// 将帧头的源MAC地址设置为本机MAC地址
							memcpy(icmp_datagram->FrameHeader.SrcMAC, icmp_datagram->FrameHeader.DesMAC, 6);

							// 将帧头的目的MAC地址设置为下一跳MAC地址
							memcpy(icmp_datagram->FrameHeader.DesMAC, next_mac, 6);

							// 减少IP头部的TTL字段，如果小于0则不发送
							icmp_datagram->IPHeader.TTL -= 1;
							if (icmp_datagram->IPHeader.TTL < 0)
							{
								return -1;
							}

							// 重新计算并设置IP头部的校验和
							calculate_checkSum(icmp_datagram);

							// 使用pcap库发送数据包
							int send_succeed = pcap_sendpacket(adhandle, (const u_char*)icmp_datagram, 74);

							// 检查发送是否成功
							if (send_succeed == 0)
							{
								// 如果发送成功，记录日志信息
								mylog.IP_print(1, icmp_datagram);
							}
						}
					}
				}
			}
		}
	}
}


int main()
{
	pcap_if_t* alldevs;//指向设备链表首部的指针
	pcap_if_t* devs_pointer;
	char errbuf[PCAP_ERRBUF_SIZE];	//错误信息缓冲区
	int devs_num = 0;//接口数量

	//打开网卡获取双IP

	/*----------------------获得本机的设备列表-------------------------*/
	printf("-------获得本机的设备列表-------\n");
	if (pcap_findalldevs_ex(PCAP_SRC_IF_STRING, 	//获取本机的接口设备
		NULL,			       //无需认证
		&alldevs, 		       //指向设备列表首部
		errbuf			      //出错信息保存缓存区
	) == -1)
	{
		//错误处理
		printf("获取本机设备错误");
		printf("%d\n", errbuf);
		pcap_freealldevs(alldevs);
		return 0;
	}
	int t = 0;
	//显示接口列表
	for (devs_pointer = alldevs; devs_pointer != NULL; devs_pointer = devs_pointer->next)
	{
		devs_num++;
		printf("%d:", devs_num);
		printf("名称：%s\n", devs_pointer->name);
		if (devs_pointer->description != NULL)//利用d->description获取该网络接口设备的描述信息
		{
			printf("描述信息：%s\n", devs_pointer->description);
		}
		else
		{
			printf("无描述信息\n");
		}
		//获取该网络接口设备的ip地址信息
		pcap_addr_t* address; // 网络适配器的地址
		for (address = devs_pointer->addresses; address != NULL; address = address->next)
		{
			switch (address->addr->sa_family)//sa_family代表了地址的类型
			{
			case AF_INET://IPV4
				printf("Address Family Name:AF_INET\t");
				if (address->addr != NULL)
				{
					//strcpy(ip, inet_ntoa(((struct sockaddr_in*)a->addr)->sin_addr));
					printf("%s\t%s\n", "IP地址:", inet_ntoa(((struct sockaddr_in*)address->addr)->sin_addr));
					printf("%s\t%s\n", "子网掩码:", inet_ntoa(((struct sockaddr_in*)address->netmask)->sin_addr));
					strcpy(my_IP[t], inet_ntoa(((struct sockaddr_in*)address->addr)->sin_addr));
					strcpy(mask[t], inet_ntoa(((struct sockaddr_in*)address->netmask)->sin_addr));
					//t++;
				}
				break;
			case AF_INET6://IPV6
				printf("Address Family Name:AF_INET6\n");
				break;
			default:
				break;
			}
			t++;
		}
		printf("\n\n");
	}
	if (devs_num == 0)
	{
		printf("无可用接口\n");
		return 0;
	}



	/*---------------------------打开选择的网卡------------------------------*/
	printf("----------打开网卡----------\n");
	printf("请输入要打开的网络接口号");
	 int open_num = 0;
	scanf("%d", &choose_dev);
	// 跳转到选中的网络接口号
	for (devs_pointer = alldevs; open_num < (choose_dev - 1); open_num++)
	{
		devs_pointer = devs_pointer->next;
	}
	//strcpy(ip0, inet_ntoa(((struct sockaddr_in*)(d->addresses)->addr)->sin_addr));
	adhandle = pcap_open(devs_pointer->name,		//设备名
		65536,		//要捕获的数据包的部分
		PCAP_OPENFLAG_PROMISCUOUS,		//混杂模式
		1000,			//超时时间
		NULL,		//远程机器验证
		errbuf		//错误缓冲池
	);
	if (adhandle == NULL)
	{
		printf("产生错误，无法打开设备\n");
		pcap_freealldevs(alldevs);
		return 0;
	}
	else
	{
		printf("打开网卡：%s\n\n", devs_pointer->description);
		pcap_freealldevs(alldevs);
	}

	for (int i = 0; i < 2; i++)
	{
		printf("%s\t", my_IP[i]);
		printf("%s\n", mask[i]);
	}


	/*---------------------------伪造ARP报文获取本机MAC----------------------*/
	printf("---------获取本机MAC并新建ARP表项--------\n");
	memset(my_MAC, 0, sizeof(my_MAC));
	//设置ARP帧的内容
	ARP_Header ARP_datagram;//ARP初始帧的声明
	//将APRFrame.FrameHeader.DesMAC设置为广播地址
	for (int i = 0; i < 6; i++)
	{
		ARP_datagram.FrameHeader.DesMAC[i] = 0xff;
	}
	for (int i = 0; i < 6; i++)
	{
		ARP_datagram.FrameHeader.SrcMAC[i] = 0x0f;
	}
	ARP_datagram.FrameHeader.FrameType = htons(0x0806);// 帧类型为ARP
	ARP_datagram.HardwareType = htons(0x0001);//硬件类型为以太网
	ARP_datagram.ProtocolType = htons(0x0800);//协议类型为IP
	ARP_datagram.HLen = 6;//硬件地址长度为6
	ARP_datagram.PLen = 4;//协议地址长为4
	ARP_datagram.Operation = htons(0x0001);//操作为ARP请求
	for (int i = 0; i < 6; i++)
	{
		ARP_datagram.SendHa[i] = 0x0f;
	}
	//将ARP_datagram.SendIP设置为本机网卡上绑定的IP地址
	ARP_datagram.SendIP = inet_addr("122.122.122.122");
	//将ARP_datagram.RecvHa设置为0
	for (int i = 0; i < 6; i++)
	{
		ARP_datagram.RecvHa[i] = 0x00;//表示目的地址未知
	}
	//将ARP_datagram.RecvIP设置为请求的IP地址
	ARP_datagram.RecvIP = inet_addr(my_IP[0]);
	//用网卡发送ARP_datagram中的内容，报文长度为sizeof(ARP_Header)，如果发送成功，返回0
	if (pcap_sendpacket(adhandle, (u_char*)&ARP_datagram, sizeof(ARP_Header)) != 0)
	{
		printf("发送失败，退出程序\n");
		return -1;
	}
	// 声明即将捕获的ARP帧
	ARP_Header* arpPacket;
	// 开始进行捕获
	while (1)
	{
		pcap_pkthdr* arp_header;
		const u_char* arp_data;
		int recv_succeed = pcap_next_ex(adhandle, &arp_header, &arp_data);
		if (recv_succeed == 1)
		{
			arpPacket = (ARP_Header*)arp_data;
			for (int i = 0; i < 6; i++)
			{
				my_MAC[i] = arpPacket->FrameHeader.SrcMAC[i];
			}
			if ((ntohs(arpPacket->FrameHeader.FrameType) == 0x0806) && (ntohs(arpPacket->Operation) == 0x0002))//如果帧类型为ARP并且操作为ARP应答
			{
				mylog.ARP_print(arpPacket);
				ArpTable::Insert_my_Arp(inet_addr(my_IP[0]), my_MAC);
				ArpTable::Insert_my_Arp(inet_addr(my_IP[1]), my_MAC);
				printf("Mac地址：\n");
				printf("%02x:%02x:%02x:%02x:%02x:%02x\n",
					arpPacket->FrameHeader.SrcMAC[0],
					arpPacket->FrameHeader.SrcMAC[1],
					arpPacket->FrameHeader.SrcMAC[2],
					arpPacket->FrameHeader.SrcMAC[3],
					arpPacket->FrameHeader.SrcMAC[4],
					arpPacket->FrameHeader.SrcMAC[5]
				);
				break;
			}
		}
	}


	RouterTable routertable;

	/*---------------------------对路由表进行操作------------------------------*/
	printf("--------------路由表操作--------------\n");
	int choice;
	while (1)
	{
		printf("可选择的路由表操作  1：添加路由表项；2：删除路由表项；3：打印路由表；4：打印ARP映射表；0：退出\n");
		printf("进行路由表操作：");
		scanf("%d", &choice);
		if (choice == 1)
		{
			RouterItem routeritem;
			char temp[30];
			printf("目的网络地址：");
			scanf("%s", &temp);
			routeritem.net = inet_addr(temp);
			printf("子网掩码：");
			scanf("%s", &temp);
			routeritem.mask = inet_addr(temp);
			printf("下一跳IP地址：");
			scanf("%s", &temp);
			routeritem.nextip = inet_addr(temp);
			routeritem.type = 1;
			routertable.Add_ritem(&routeritem);
		}
		else if (choice == 2)
		{
			printf("请输入删除表项编号：");
			int number;
			scanf("%d", &number);
			routertable.Delate_ritem(number);
		}
		else if (choice == 3)
		{
			routertable.print();
		}
		else if (choice == 4)
		{
			ArpTable::PrintArpTable();
		}
		else if (choice == 0)
		{
			break;
		}
		else
		{
			printf("无效操作，请重新选择\n");
		}
	}
	int result = Forward(routertable);
	pcap_close(adhandle);
	return 0;
}