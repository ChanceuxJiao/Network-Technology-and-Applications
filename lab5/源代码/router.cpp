#pragma warning(disable : 4996)
#include "pcap.h"
#include "router.h"//��־

//using namespace std;


// �������ڼ��㲢����IPͷ����У���
void calculate_checkSum(Datagram* temp)
{
	// ��IPͷ����У����ֶγ�ʼ��Ϊ0
	temp->IPHeader.Checksum = 0;

	// ���ڴ洢У��͵ı�������ʼ��Ϊ0
	unsigned int sum = 0;

	// ��IPͷ���ṹ��ǿ��ת��ΪWORD�������飬ÿ16λΪһ��
	WORD* t = (WORD*)&temp->IPHeader;

	// ѭ������ÿһ��16λ�������ۼӺ�
	for (int i = 0; i < sizeof(IP_Header) / 2; i++)
	{
		sum += t[i];

		// ����ۼӺ����������лؾ�
		while (sum >= 0x10000)
		{
			int s = sum >> 16;
			sum -= 0x10000;
			sum += s;
		}
	}

	// ������õ����ۼӺͰ�λȡ����������ΪIPͷ����У���
	temp->IPHeader.Checksum = ~sum;
}


// �������ڼ��IPͷ����У����Ƿ���Ч
bool verify_checkSum(Datagram* temp)
{
	// ���ڴ洢У��͵ı�������ʼ��Ϊ0
	unsigned int sum = 0;

	// ��IPͷ���ṹ��ǿ��ת��ΪWORD�������飬ÿ16λΪһ��
	WORD* t = (WORD*)&temp->IPHeader;

	// ѭ������ÿһ��16λ�������ۼӺ�
	for (int i = 0; i < sizeof(IP_Header) / 2; i++)
	{
		sum += t[i];

		// ����ۼӺ����������лؾ�
		while (sum >= 0x10000)
		{
			int s = sum >> 16;
			sum -= 0x10000;
			sum += s;
		}
	}

	// ���У����Ƿ�Ϊ0xFFFF (65535)��������򷵻� true����ʾ��Ч
	if (sum == 65535)
	{
		return true;
	}
	else
	{
		return false;
	}
}


//�Ա�MAC��ַ�Ƿ���ͬ
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
//·��ת���߳�
DWORD WINAPI Forward_Thread(LPVOID lparam)
{
	RouterTable routertable = *(RouterTable*)(LPVOID)lparam;
	pcap_pkthdr* recv_header;
	const u_char* recv_data;
	while (1)
	{
			int recv_succeed = pcap_next_ex(adhandle, &recv_header, &recv_data);
			if (recv_succeed)//���յ���Ϣ
			{
				Frame_Header* header = (Frame_Header*)recv_data;
				if (is_my_MAC(header->DesMAC, my_MAC)&& ntohs(header->FrameType) == 0x0800)//ȷ���Ƿ����Լ������ݰ��������ݰ��������IPv4
				{
						Datagram* data_gram = (Datagram*)recv_data;
						mylog.IP_print(0, data_gram);
						DWORD destip = data_gram->IPHeader.DstIP;
						DWORD route_next_ip = routertable.RouterFind(destip);//�����Ƿ��ж�Ӧ����õ���һ��IP��ַ
						if (route_next_ip == -1)
						{
							continue;
						}
						if (verify_checkSum(data_gram))//���У��Ͳ���ȷ����ֱ�Ӷ��������д���
						{
							if (data_gram->IPHeader.DstIP != inet_addr(my_IP[0]) && data_gram->IPHeader.DstIP != inet_addr(my_IP[1]))//������Ƿ���·�����Լ��ģ���ô��Ҫת��
							{
									//ICMP_Datagram���İ���IP���ݰ���ͷ����������
									ICMP_Datagram_t* data_p = (ICMP_Datagram_t*)recv_data;
									ICMP_Datagram_t data_t = *data_p;
									BYTE next_mac[6];
									if (route_next_ip == 0)//��һ����0��ֱ��Ͷ��
									{
										//���ARP����û���������ݣ�����Ҫ��ȡARP
										if (!ArpTable::FindArp(destip, next_mac))
										{
											ArpTable::Insert_other_Arp(destip, next_mac);
										}
											// ��ICMP���ݱ�ת��ΪDatagram�ṹ��
										Datagram* icmp_datagram = (Datagram*)&data_t;

										// ��֡ͷ��ԴMAC��ַ����Ϊ����MAC��ַ
										memcpy(icmp_datagram->FrameHeader.SrcMAC, icmp_datagram->FrameHeader.DesMAC, 6);

										// ��֡ͷ��Ŀ��MAC��ַ����Ϊ��һ��MAC��ַ
										memcpy(icmp_datagram->FrameHeader.DesMAC, next_mac, 6);

										// ����IPͷ����TTL�ֶΣ����С��0�򲻷���
										icmp_datagram->IPHeader.TTL -= 1;
										if (icmp_datagram->IPHeader.TTL < 0)
										{
											return -1;
										}

										// ���¼��㲢����IPͷ����У���
										calculate_checkSum(icmp_datagram);

										// ʹ��pcap�ⷢ�����ݰ�
										int send_succeed = pcap_sendpacket(adhandle, (const u_char*)icmp_datagram, 74);

										// ��鷢���Ƿ�ɹ�
										if (send_succeed == 0)
										{
											// ������ͳɹ�����¼��־��Ϣ
											mylog.IP_print(1, icmp_datagram);
										}
									}

									else if (route_next_ip != -1)//��ֱ��Ͷ�ݣ�������һ��IP��MAC
									{
										if (!ArpTable::FindArp(route_next_ip, next_mac))
										{
											ArpTable::Insert_other_Arp(route_next_ip, next_mac);
										}
											// ��ICMP���ݱ�ת��ΪDatagram�ṹ��
										Datagram* icmp_datagram = (Datagram*)&data_t;

										// ��֡ͷ��ԴMAC��ַ����Ϊ����MAC��ַ
										memcpy(icmp_datagram->FrameHeader.SrcMAC, icmp_datagram->FrameHeader.DesMAC, 6);

										// ��֡ͷ��Ŀ��MAC��ַ����Ϊ��һ��MAC��ַ
										memcpy(icmp_datagram->FrameHeader.DesMAC, next_mac, 6);

										// ����IPͷ����TTL�ֶΣ����С��0�򲻷���
										icmp_datagram->IPHeader.TTL -= 1;
										if (icmp_datagram->IPHeader.TTL < 0)
										{
											return -1;
										}

										// ���¼��㲢����IPͷ����У���
										calculate_checkSum(icmp_datagram);

										// ʹ��pcap�ⷢ�����ݰ�
										int send_succeed = pcap_sendpacket(adhandle, (const u_char*)icmp_datagram, 74);

										// ��鷢���Ƿ�ɹ�
										if (send_succeed == 0)
										{
											// ������ͳɹ�����¼��־��Ϣ
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

//·��ת���߳�
DWORD Forward(RouterTable routertable)
{
	//RouterTable routertable = *(RouterTable*)(LPVOID)lparam;
	pcap_pkthdr* recv_header;
	const u_char* recv_data;
	while (1)
	{
		int recv_succeed = pcap_next_ex(adhandle, &recv_header, &recv_data);
		if (recv_succeed==1)//���յ���Ϣ
		{
			Frame_Header* header = (Frame_Header*)recv_data;
			if (ntohs(header->FrameType) == 0x0800)//���ݰ��������IPv4,IP���ݰ�
			{
				Datagram* data_gram = (Datagram*)recv_data;
				mylog.IP_print(0, data_gram);
				DWORD destip = data_gram->IPHeader.DstIP;
				DWORD route_next_ip = routertable.RouterFind(destip);//�����Ƿ��ж�Ӧ����õ���һ��IP��ַ
				if (route_next_ip == -1)
				{
					continue;
				}
				if (verify_checkSum(data_gram))//���У��Ͳ���ȷ����ֱ�Ӷ��������д���
				{
					if (data_gram->IPHeader.DstIP != inet_addr(my_IP[0]) && data_gram->IPHeader.DstIP != inet_addr(my_IP[1]))//������Ƿ���·�����Լ��ģ���ô��Ҫת��
					{
						//ICMP_Datagram���İ���IP���ݰ���ͷ����������
						ICMP_Datagram_t* data_p = (ICMP_Datagram_t*)recv_data;
						ICMP_Datagram_t data_t = *data_p;
						BYTE next_mac[6];
						if (route_next_ip == 0)//��һ����0��ֱ��Ͷ��
						{
							//���ARP����û���������ݣ�����Ҫ��ȡARP
							if (!ArpTable::FindArp(destip, next_mac))
							{
								ArpTable::Insert_other_Arp(destip, next_mac);
							}
							// ��ICMP���ݱ�ת��ΪDatagram�ṹ��
							Datagram* icmp_datagram = (Datagram*)&data_t;

							// ��֡ͷ��ԴMAC��ַ����Ϊ����MAC��ַ
							memcpy(icmp_datagram->FrameHeader.SrcMAC, icmp_datagram->FrameHeader.DesMAC, 6);

							// ��֡ͷ��Ŀ��MAC��ַ����Ϊ��һ��MAC��ַ
							memcpy(icmp_datagram->FrameHeader.DesMAC, next_mac, 6);

							// ����IPͷ����TTL�ֶΣ����С��0�򲻷���
							icmp_datagram->IPHeader.TTL -= 1;
							if (icmp_datagram->IPHeader.TTL < 0)
							{
								return -1;
							}

							// ���¼��㲢����IPͷ����У���
							calculate_checkSum(icmp_datagram);

							// ʹ��pcap�ⷢ�����ݰ�
							int send_succeed = pcap_sendpacket(adhandle, (const u_char*)icmp_datagram, 74);

							// ��鷢���Ƿ�ɹ�
							if (send_succeed == 0)
							{
								// ������ͳɹ�����¼��־��Ϣ
								mylog.IP_print(1, icmp_datagram);
							}
						}

						else if (route_next_ip != -1)//��ֱ��Ͷ�ݣ�������һ��IP��MAC
						{
							if (!ArpTable::FindArp(route_next_ip, next_mac))
							{							
								//���ARP����û���������ݣ�����Ҫ��ȡARP
								ArpTable::Insert_other_Arp(route_next_ip, next_mac);
							}
							// ��ICMP���ݱ�ת��ΪDatagram�ṹ��
							Datagram* icmp_datagram = (Datagram*)&data_t;

							// ��֡ͷ��ԴMAC��ַ����Ϊ����MAC��ַ
							memcpy(icmp_datagram->FrameHeader.SrcMAC, icmp_datagram->FrameHeader.DesMAC, 6);

							// ��֡ͷ��Ŀ��MAC��ַ����Ϊ��һ��MAC��ַ
							memcpy(icmp_datagram->FrameHeader.DesMAC, next_mac, 6);

							// ����IPͷ����TTL�ֶΣ����С��0�򲻷���
							icmp_datagram->IPHeader.TTL -= 1;
							if (icmp_datagram->IPHeader.TTL < 0)
							{
								return -1;
							}

							// ���¼��㲢����IPͷ����У���
							calculate_checkSum(icmp_datagram);

							// ʹ��pcap�ⷢ�����ݰ�
							int send_succeed = pcap_sendpacket(adhandle, (const u_char*)icmp_datagram, 74);

							// ��鷢���Ƿ�ɹ�
							if (send_succeed == 0)
							{
								// ������ͳɹ�����¼��־��Ϣ
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
	pcap_if_t* alldevs;//ָ���豸�����ײ���ָ��
	pcap_if_t* devs_pointer;
	char errbuf[PCAP_ERRBUF_SIZE];	//������Ϣ������
	int devs_num = 0;//�ӿ�����

	//��������ȡ˫IP

	/*----------------------��ñ������豸�б�-------------------------*/
	printf("-------��ñ������豸�б�-------\n");
	if (pcap_findalldevs_ex(PCAP_SRC_IF_STRING, 	//��ȡ�����Ľӿ��豸
		NULL,			       //������֤
		&alldevs, 		       //ָ���豸�б��ײ�
		errbuf			      //������Ϣ���滺����
	) == -1)
	{
		//������
		printf("��ȡ�����豸����");
		printf("%d\n", errbuf);
		pcap_freealldevs(alldevs);
		return 0;
	}
	int t = 0;
	//��ʾ�ӿ��б�
	for (devs_pointer = alldevs; devs_pointer != NULL; devs_pointer = devs_pointer->next)
	{
		devs_num++;
		printf("%d:", devs_num);
		printf("���ƣ�%s\n", devs_pointer->name);
		if (devs_pointer->description != NULL)//����d->description��ȡ������ӿ��豸��������Ϣ
		{
			printf("������Ϣ��%s\n", devs_pointer->description);
		}
		else
		{
			printf("��������Ϣ\n");
		}
		//��ȡ������ӿ��豸��ip��ַ��Ϣ
		pcap_addr_t* address; // �����������ĵ�ַ
		for (address = devs_pointer->addresses; address != NULL; address = address->next)
		{
			switch (address->addr->sa_family)//sa_family�����˵�ַ������
			{
			case AF_INET://IPV4
				printf("Address Family Name:AF_INET\t");
				if (address->addr != NULL)
				{
					//strcpy(ip, inet_ntoa(((struct sockaddr_in*)a->addr)->sin_addr));
					printf("%s\t%s\n", "IP��ַ:", inet_ntoa(((struct sockaddr_in*)address->addr)->sin_addr));
					printf("%s\t%s\n", "��������:", inet_ntoa(((struct sockaddr_in*)address->netmask)->sin_addr));
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
		printf("�޿��ýӿ�\n");
		return 0;
	}



	/*---------------------------��ѡ�������------------------------------*/
	printf("----------������----------\n");
	printf("������Ҫ�򿪵�����ӿں�");
	 int open_num = 0;
	scanf("%d", &choose_dev);
	// ��ת��ѡ�е�����ӿں�
	for (devs_pointer = alldevs; open_num < (choose_dev - 1); open_num++)
	{
		devs_pointer = devs_pointer->next;
	}
	//strcpy(ip0, inet_ntoa(((struct sockaddr_in*)(d->addresses)->addr)->sin_addr));
	adhandle = pcap_open(devs_pointer->name,		//�豸��
		65536,		//Ҫ��������ݰ��Ĳ���
		PCAP_OPENFLAG_PROMISCUOUS,		//����ģʽ
		1000,			//��ʱʱ��
		NULL,		//Զ�̻�����֤
		errbuf		//���󻺳��
	);
	if (adhandle == NULL)
	{
		printf("���������޷����豸\n");
		pcap_freealldevs(alldevs);
		return 0;
	}
	else
	{
		printf("��������%s\n\n", devs_pointer->description);
		pcap_freealldevs(alldevs);
	}

	for (int i = 0; i < 2; i++)
	{
		printf("%s\t", my_IP[i]);
		printf("%s\n", mask[i]);
	}


	/*---------------------------α��ARP���Ļ�ȡ����MAC----------------------*/
	printf("---------��ȡ����MAC���½�ARP����--------\n");
	memset(my_MAC, 0, sizeof(my_MAC));
	//����ARP֡������
	ARP_Header ARP_datagram;//ARP��ʼ֡������
	//��APRFrame.FrameHeader.DesMAC����Ϊ�㲥��ַ
	for (int i = 0; i < 6; i++)
	{
		ARP_datagram.FrameHeader.DesMAC[i] = 0xff;
	}
	for (int i = 0; i < 6; i++)
	{
		ARP_datagram.FrameHeader.SrcMAC[i] = 0x0f;
	}
	ARP_datagram.FrameHeader.FrameType = htons(0x0806);// ֡����ΪARP
	ARP_datagram.HardwareType = htons(0x0001);//Ӳ������Ϊ��̫��
	ARP_datagram.ProtocolType = htons(0x0800);//Э������ΪIP
	ARP_datagram.HLen = 6;//Ӳ����ַ����Ϊ6
	ARP_datagram.PLen = 4;//Э���ַ��Ϊ4
	ARP_datagram.Operation = htons(0x0001);//����ΪARP����
	for (int i = 0; i < 6; i++)
	{
		ARP_datagram.SendHa[i] = 0x0f;
	}
	//��ARP_datagram.SendIP����Ϊ���������ϰ󶨵�IP��ַ
	ARP_datagram.SendIP = inet_addr("122.122.122.122");
	//��ARP_datagram.RecvHa����Ϊ0
	for (int i = 0; i < 6; i++)
	{
		ARP_datagram.RecvHa[i] = 0x00;//��ʾĿ�ĵ�ַδ֪
	}
	//��ARP_datagram.RecvIP����Ϊ�����IP��ַ
	ARP_datagram.RecvIP = inet_addr(my_IP[0]);
	//����������ARP_datagram�е����ݣ����ĳ���Ϊsizeof(ARP_Header)��������ͳɹ�������0
	if (pcap_sendpacket(adhandle, (u_char*)&ARP_datagram, sizeof(ARP_Header)) != 0)
	{
		printf("����ʧ�ܣ��˳�����\n");
		return -1;
	}
	// �������������ARP֡
	ARP_Header* arpPacket;
	// ��ʼ���в���
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
			if ((ntohs(arpPacket->FrameHeader.FrameType) == 0x0806) && (ntohs(arpPacket->Operation) == 0x0002))//���֡����ΪARP���Ҳ���ΪARPӦ��
			{
				mylog.ARP_print(arpPacket);
				ArpTable::Insert_my_Arp(inet_addr(my_IP[0]), my_MAC);
				ArpTable::Insert_my_Arp(inet_addr(my_IP[1]), my_MAC);
				printf("Mac��ַ��\n");
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

	/*---------------------------��·�ɱ���в���------------------------------*/
	printf("--------------·�ɱ����--------------\n");
	int choice;
	while (1)
	{
		printf("��ѡ���·�ɱ����  1�����·�ɱ��2��ɾ��·�ɱ��3����ӡ·�ɱ�4����ӡARPӳ���0���˳�\n");
		printf("����·�ɱ������");
		scanf("%d", &choice);
		if (choice == 1)
		{
			RouterItem routeritem;
			char temp[30];
			printf("Ŀ�������ַ��");
			scanf("%s", &temp);
			routeritem.net = inet_addr(temp);
			printf("�������룺");
			scanf("%s", &temp);
			routeritem.mask = inet_addr(temp);
			printf("��һ��IP��ַ��");
			scanf("%s", &temp);
			routeritem.nextip = inet_addr(temp);
			routeritem.type = 1;
			routertable.Add_ritem(&routeritem);
		}
		else if (choice == 2)
		{
			printf("������ɾ�������ţ�");
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
			printf("��Ч������������ѡ��\n");
		}
	}
	int result = Forward(routertable);
	pcap_close(adhandle);
	return 0;
}