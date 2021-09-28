/*
	##########################
	  >>> CODED BY DARXIS <<<
			   v2.0
	- Дата: 26.09.2021 [2:27]
	##########################
*/

#include <math.h>
#include <fcntl.h>
#include <stdio.h>
#include <fstream>
#include <netdb.h>
#include <locale.h>
#include <string.h>
#include <resolv.h>
#include <unistd.h>
#include <iostream>
#include <arpa/inet.h>
#include <netinet/ip_icmp.h>

#define PRINT_ERROR_STATUS(x...) cout << "\033[1;31m" << x << "\033[0m" << endl;
#define PRINT_SUCCESS_STATUS(x...) cout << "\033[1;32m" << x << "\033[0m" << endl;
#define PRINT_TEXT_MESSAGE(x...) cout << "\033[1;33m" << x << "\033[0m" << endl;

pthread_t LINUX_DAEMON_THREAD[2];
pthread_t SCANNER_NETWORK_THREAD[1024];
typedef struct { uint32_t INPUT_IP_ADDRESS; } IP_ADDRESS_TABLE;

char* GLOBAL_IP_ADDRESS;
char* IP_TO_CHECK;
bool SCAN_STATUS = false;

using namespace std;

class __FUNCTIONS
{
public:
	int WRITE_TO_LOG(char* INPUT_STATUS)
	{
		try
		{
			time_t GET_RAW_TIME;
			ofstream GET_FILE_SAVER;
			struct tm* GET_TIME_STRUCT;

			string GET_STATUS = INPUT_STATUS;
			string GET_LOGFILE_PATH = "SCANNER_LOG_FILE.log";

			time(&GET_RAW_TIME);
			GET_TIME_STRUCT = localtime(&GET_RAW_TIME);

			GET_FILE_SAVER.open(GET_LOGFILE_PATH, ios_base::app);

			if (!GET_FILE_SAVER.is_open())
			{
				PRINT_ERROR_STATUS("[-] Ошибка!> В функции saveToLogFile() не выполняется открытие лог-файла!");
				return -1;
			}
			else
			{
				GET_FILE_SAVER << "        " << endl;
				GET_FILE_SAVER << "===================================================" << endl;
				GET_FILE_SAVER << "[*] ДАТА: " << asctime(GET_TIME_STRUCT);
				GET_FILE_SAVER << "[*] СТАТУС: " << GET_STATUS << endl;
				GET_FILE_SAVER << "===================================================" << endl;
				GET_FILE_SAVER << "        " << endl;
				GET_FILE_SAVER.flush();
				GET_FILE_SAVER.close();
				return 0;
			}
		}
		catch (...)
		{
			PRINT_ERROR_STATUS("[-] Ошибка!> В функции WRITE_TO_LOG() произошла ошибка исключения!");
			return -2;
		}
	}

public:
	int CALL_SERVICE_SCAN(char* INPUT_IP_ADDRESS, ushort INPUT_PORT)
	{
		try
		{
			char* REMOTE_HOST = INPUT_IP_ADDRESS;
			ushort REMOTE_PORT = INPUT_PORT;

			short int CONNECTION_HANDLER;
			fd_set NETWORK_DESCRIPTOR;

			struct timeval CONNECTION_TIMEOUT;
			struct sockaddr_in NETWORK_PACKET_STRUCT;

			NETWORK_PACKET_STRUCT.sin_family = AF_INET;
			NETWORK_PACKET_STRUCT.sin_addr.s_addr = inet_addr(REMOTE_HOST);
			NETWORK_PACKET_STRUCT.sin_port = htons(REMOTE_PORT);

			CONNECTION_HANDLER = socket(AF_INET, SOCK_STREAM, 0);
			fcntl(CONNECTION_HANDLER, F_SETFL, O_NONBLOCK);

			connect(CONNECTION_HANDLER, (struct sockaddr*)&NETWORK_PACKET_STRUCT, sizeof(NETWORK_PACKET_STRUCT));

			FD_ZERO(&NETWORK_DESCRIPTOR);
			FD_SET(CONNECTION_HANDLER, &NETWORK_DESCRIPTOR);

			CONNECTION_TIMEOUT.tv_sec = 15;
			CONNECTION_TIMEOUT.tv_usec = 0;

			if (select(CONNECTION_HANDLER + 1, NULL, &NETWORK_DESCRIPTOR, NULL, &CONNECTION_TIMEOUT) == 1)
			{
				int ERROR_STATUS;

				__socklen_t TIMEOUT_COUNTER = sizeof(ERROR_STATUS);

				getsockopt(CONNECTION_HANDLER, SOL_SOCKET, SO_ERROR, &ERROR_STATUS, &TIMEOUT_COUNTER);

				if (ERROR_STATUS == 0)
				{
					close(CONNECTION_HANDLER);
					return 0;
				}
				else
				{
					close(CONNECTION_HANDLER);
					return -1;
				}
			}
			close(CONNECTION_HANDLER);
			return -2;
		}
		catch (...)
		{
			PRINT_ERROR_STATUS("[-] Ошибка!> В функции CALL_SERVICE_SCAN() произошла ошибка исключения!");
			return -3;
		}
	}

private:
	uint16_t NETWORK_PACKET_CHECKSUM(uint16_t* GET_INPUT_PACKET, unsigned GET_INPUT_PACKET_SIZE)
	{
		try
		{
			uint16_t GET_RESULT = 0;
			uint32_t GET_PACKET_SUMARY = 0;

			while (GET_INPUT_PACKET_SIZE > 1)
			{
				GET_PACKET_SUMARY += *GET_INPUT_PACKET++;
				GET_INPUT_PACKET_SIZE -= 2;
			}

			if (GET_INPUT_PACKET_SIZE == 1)
			{
				*(unsigned char*)&GET_RESULT = *(unsigned char*)GET_INPUT_PACKET;
				GET_PACKET_SUMARY += GET_RESULT;
			}

			GET_PACKET_SUMARY = (GET_PACKET_SUMARY >> 16) + (GET_PACKET_SUMARY & 0xFFFF);
			GET_PACKET_SUMARY += (GET_PACKET_SUMARY >> 16);
			GET_RESULT = ~GET_PACKET_SUMARY;

			return GET_RESULT;
		}
		catch (...)
		{
			PRINT_ERROR_STATUS("[-] Ошибка!> В функции NETWORK_PACKET_CHECKSUM() произошла ошибка исключения!");
			return -1;
		}
	}

public:
	int CALL_ICMP_SCAN(char* INPUT_IP_ADDRESS)
	{
		try
		{
			char* REMOTE_HOST = INPUT_IP_ADDRESS;

			int CONNECTION_HANDLER;
			int CONNECTION_CRASH_COUNTER;
			int GET_PACKET_MTU;
			int GET_PACKET_STRUCT_SIZE;
			int GET_DATA_SIZE = 64 - ICMP_MINLEN;

			struct hostent* GET_HOST_NAME;
			struct sockaddr_in STRUCT_EGRESS_PACKET;
			struct sockaddr_in STRUCT_INGRESS_PACKET;

			u_char* GET_NETWORK_PACKET;
			u_char* GET_DATA_OUTPACK[65536 - 60 - ICMP_MINLEN];

			char GET_HOSTNAME_BUFFER[MAXHOSTNAMELEN];

			string GET_HOSTNAME_OF_IP;

			struct ip* GET_IP;
			struct icmp* GET_ICMP_STRUCT;

			int GET_RETURN;
			int ENGRESS_PACKET_SIZE;
			int PACKET_HEADER_SIZE;

			fd_set NETWORK_DESCRIPTOR;
			struct timeval CONNECTION_TIMEOUT;

			int GET_RETVAL;

			STRUCT_EGRESS_PACKET.sin_family = AF_INET;
			STRUCT_EGRESS_PACKET.sin_addr.s_addr = inet_addr(REMOTE_HOST);

			if (STRUCT_EGRESS_PACKET.sin_addr.s_addr != (u_int)-1)
			{
				GET_HOSTNAME_OF_IP = REMOTE_HOST;
			}
			else
			{
				GET_HOST_NAME = gethostbyname(REMOTE_HOST);

				STRUCT_EGRESS_PACKET.sin_family = GET_HOST_NAME->h_addrtype;
				bcopy(GET_HOST_NAME->h_addr, (caddr_t)&STRUCT_EGRESS_PACKET.sin_addr, GET_HOST_NAME->h_length);
				strncpy(GET_HOSTNAME_BUFFER, GET_HOST_NAME->h_name, sizeof(GET_HOSTNAME_BUFFER) - 1);
				GET_HOSTNAME_OF_IP = GET_HOSTNAME_BUFFER;
			}

			GET_PACKET_STRUCT_SIZE = GET_DATA_SIZE + 60 + 76;

			if ((GET_NETWORK_PACKET = (u_char*)malloc((u_int)GET_PACKET_STRUCT_SIZE)) == NULL)
			{
				PRINT_ERROR_STATUS("[-] Ошибка!> В функции CALL_ICMP_SCAN() произошла ошибка генерации malloc функции!");
				close(CONNECTION_HANDLER);
				return -1;
			}

			if ((CONNECTION_HANDLER = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP)) < 0)
			{
				if (CONNECTION_CRASH_COUNTER < 0)
				{
					PRINT_ERROR_STATUS("[-] Ошибка!> В функции CALL_ICMP_SCAN() произошла ошибка генерации ICMP запроса!");
					close(CONNECTION_HANDLER);
					return -2;
				}
			}

			GET_ICMP_STRUCT = (struct icmp*)GET_DATA_OUTPACK;
			GET_ICMP_STRUCT->icmp_type = ICMP_ECHO;
			GET_ICMP_STRUCT->icmp_code = 0;
			GET_ICMP_STRUCT->icmp_cksum = 0;
			GET_ICMP_STRUCT->icmp_seq = 12345;
			GET_ICMP_STRUCT->icmp_id = getpid();


			GET_PACKET_MTU = GET_DATA_SIZE + ICMP_MINLEN;
			GET_ICMP_STRUCT->icmp_cksum = NETWORK_PACKET_CHECKSUM((unsigned short*)GET_ICMP_STRUCT, GET_PACKET_MTU);

			CONNECTION_CRASH_COUNTER = sendto(CONNECTION_HANDLER, (char*)GET_DATA_OUTPACK, GET_PACKET_MTU, 0, (struct sockaddr*)&STRUCT_EGRESS_PACKET, (socklen_t)sizeof(struct sockaddr_in));

			if (CONNECTION_CRASH_COUNTER < 0 || CONNECTION_CRASH_COUNTER != GET_PACKET_MTU)
			{
				if (CONNECTION_CRASH_COUNTER < 0)
				{
					close(CONNECTION_HANDLER);
					return -3;
				}
			}

			FD_ZERO(&NETWORK_DESCRIPTOR);
			FD_SET(CONNECTION_HANDLER, &NETWORK_DESCRIPTOR);

			CONNECTION_TIMEOUT.tv_sec = 1;
			CONNECTION_TIMEOUT.tv_usec = 0;

			GET_RETVAL = select(CONNECTION_HANDLER + 1, &NETWORK_DESCRIPTOR, NULL, NULL, &CONNECTION_TIMEOUT);
			if (GET_RETVAL == -1)
			{
				close(CONNECTION_HANDLER);
				return -4;
			}
			else if (GET_RETVAL)
			{
				ENGRESS_PACKET_SIZE = sizeof(sockaddr_in);

				if ((GET_RETURN = recvfrom(CONNECTION_HANDLER, (char*)GET_NETWORK_PACKET, GET_PACKET_STRUCT_SIZE, 0, (struct sockaddr*)&STRUCT_INGRESS_PACKET, (socklen_t*)&ENGRESS_PACKET_SIZE)) < 0)
				{
					PRINT_ERROR_STATUS("[-] Ошибка!> В функции CALL_ICMP_SCAN() произошла ошибка в обработке ICMP запроса!");
					close(CONNECTION_HANDLER);
					return -5;
				}
				else
				{
					GET_IP = (struct ip*)((char*)GET_NETWORK_PACKET);
					PACKET_HEADER_SIZE = sizeof(struct ip);
					GET_ICMP_STRUCT = (struct icmp*)(GET_NETWORK_PACKET + PACKET_HEADER_SIZE);

					if (GET_ICMP_STRUCT->icmp_type == ICMP_ECHOREPLY)
					{
						close(CONNECTION_HANDLER);
						return 0;
					}
					else
					{
						close(CONNECTION_HANDLER);
						return -6;
					}
				}
			}
		}
		catch (...)
		{
			PRINT_ERROR_STATUS("[-] Ошибка!> В функции CALL_ICMP_SCAN() произошла ошибка исключения!");
			return -7;
		}
	}
};

class __ACTIONS
{
public:
	void* START_PING_SCAN()
	{
		__FUNCTIONS CALL_FUNCTION;

		try
		{
			char* REMOTE_HOST = GLOBAL_IP_ADDRESS;

			if (CALL_FUNCTION.CALL_ICMP_SCAN(REMOTE_HOST) == 0)
			{
				CALL_FUNCTION.WRITE_TO_LOG("[+] Успешно!> Была вызвана функция START_PING_SCAN() в программе!");
				SCAN_STATUS = true;
				return 0;
			}
			else
			{
				CALL_FUNCTION.WRITE_TO_LOG("[+] Успешно!> Была вызвана функция START_PING_SCAN() в программе!");
				return 0;
			}
		}
		catch (...)
		{
			PRINT_ERROR_STATUS("[-] Ошибка!> В функции START_PING_SCAN() произошла ошибка исключения!");
			CALL_FUNCTION.WRITE_TO_LOG("[-] Ошибка!> В функции START_PING_SCAN() произошла ошибка исключения!");
			exit(-1);
		}
	}

public:
	void* START_TELNET_SCAN()
	{
		__FUNCTIONS CALL_FUNCTION;

		try
		{
			char* REMOTE_HOST = GLOBAL_IP_ADDRESS;
			ushort REMOTE_PORT = 23;

			if (CALL_FUNCTION.CALL_SERVICE_SCAN(REMOTE_HOST, REMOTE_PORT) == 0)
			{
				CALL_FUNCTION.WRITE_TO_LOG("[+] Успешно!> Была вызвана функция START_TELNET_SCAN() в программе!");
				SCAN_STATUS = true;
				return 0;
			}
			else
			{
				CALL_FUNCTION.WRITE_TO_LOG("[+] Успешно!> Была вызвана функция START_TELNET_SCAN() в программе!");
				return 0;
			}
		}
		catch (...)
		{
			PRINT_ERROR_STATUS("[-] Ошибка!> В функции START_TELNET_SCAN() произошла ошибка исключения!");
			CALL_FUNCTION.WRITE_TO_LOG("[-] Ошибка!> В функции START_TELNET_SCAN() произошла ошибка исключения!");
			exit(-1);
		}
	}

public:
	void* START_SSH_SCAN()
	{
		__FUNCTIONS CALL_FUNCTION;

		try
		{
			char* REMOTE_HOST = GLOBAL_IP_ADDRESS;
			ushort REMOTE_PORT = 22;

			if (CALL_FUNCTION.CALL_SERVICE_SCAN(REMOTE_HOST, REMOTE_PORT) == 0)
			{
				CALL_FUNCTION.WRITE_TO_LOG("[+] Успешно!> Была вызвана функция START_SSH_SCAN() в программе!");
				SCAN_STATUS = true;
				return 0;
			}
			else
			{
				CALL_FUNCTION.WRITE_TO_LOG("[+] Успешно!> Была вызвана функция START_SSH_SCAN() в программе!");
				return 0;
			}
		}
		catch (...)
		{
			PRINT_ERROR_STATUS("[-] Ошибка!> В функции START_SSH_SCAN() произошла ошибка исключения!");
			CALL_FUNCTION.WRITE_TO_LOG("[-] Ошибка!> В функции START_SSH_SCAN() произошла ошибка исключения!");
			exit(-1);
		}
	}

public:
	void* START_HTTP_SCAN()
	{
		__FUNCTIONS CALL_FUNCTION;

		try
		{
			char* REMOTE_HOST = GLOBAL_IP_ADDRESS;
			ushort REMOTE_PORT = 80;

			if (CALL_FUNCTION.CALL_SERVICE_SCAN(REMOTE_HOST, REMOTE_PORT) == 0)
			{
				CALL_FUNCTION.WRITE_TO_LOG("[+] Успешно!> Была вызвана функция START_HTTP_SCAN() в программе!");
				SCAN_STATUS = true;
				return 0;
			}
			else
			{
				CALL_FUNCTION.WRITE_TO_LOG("[+] Успешно!> Была вызвана функция START_HTTP_SCAN() в программе!");
				return 0;
			}
		}
		catch (...)
		{
			PRINT_ERROR_STATUS("[-] Ошибка!> В функции START_HTTP_SCAN() произошла ошибка исключения!");
			CALL_FUNCTION.WRITE_TO_LOG("[-] Ошибка!> В функции START_HTTP_SCAN() произошла ошибка исключения!");
			exit(-1);
		}
	}
};

class __TOOLS
{
public:
	void CONVERT_TO_BYTES(uint32_t INPUT_VALUE, uint8_t* INPUT_STRUCT)
	{
		__FUNCTIONS CALL_FUNCTION;

		try
		{
			INPUT_STRUCT[0] = (uint8_t)INPUT_VALUE;
			INPUT_STRUCT[1] = (uint8_t)(INPUT_VALUE >> 8);
			INPUT_STRUCT[2] = (uint8_t)(INPUT_VALUE >> 16);
			INPUT_STRUCT[3] = (uint8_t)(INPUT_VALUE >> 24);
		}
		catch (...)
		{
			PRINT_ERROR_STATUS("[-] Ошибка!> В функции convertToBytes() произошла ошибка исключения!");
			CALL_FUNCTION.WRITE_TO_LOG("[-] Ошибка!> В функции convertToBytes() произошла ошибка исключения!");
			exit(-1);
		}
	}

public:
	int SUBNET_MASK_PARSER(char* INPUT_IP_ADDRESS, uint32_t* SPLITED_SUBNET_MASK, uint32_t* SPLITED_SUBNET_MASK_SIZE)
	{
		__FUNCTIONS CALL_FUNCTION;

		try
		{
			int GET_RESULT;
			uint8_t GET_IP_ADDRESS_MASK[4] = { 0,0,0,0 };

			GET_RESULT = sscanf(INPUT_IP_ADDRESS, "%hhd.%hhd.%hhd.%hhd/%d", &GET_IP_ADDRESS_MASK[0], &GET_IP_ADDRESS_MASK[1], &GET_IP_ADDRESS_MASK[2], &GET_IP_ADDRESS_MASK[3], SPLITED_SUBNET_MASK_SIZE);

			if (GET_RESULT < 0)
			{
				return GET_RESULT;
			}
			else
			{
				*SPLITED_SUBNET_MASK = 0x00;
				*SPLITED_SUBNET_MASK = GET_IP_ADDRESS_MASK[0] | (GET_IP_ADDRESS_MASK[1] << 8) | (GET_IP_ADDRESS_MASK[2] << 16) | (GET_IP_ADDRESS_MASK[3] << 24);

				return GET_RESULT;
			}
		}
		catch (...)
		{
			PRINT_ERROR_STATUS("[-] Ошибка!> В функции subnetMaskParser() произошла ошибка исключения!");
			CALL_FUNCTION.WRITE_TO_LOG("[-] Ошибка!> В функции subnetMaskParser() произошла ошибка исключения!");
			exit(-1);
		}
	}

public:
	char* CONVERT_IP_TO_STRING(uint32_t inputIpAddress)
	{
		__FUNCTIONS CALL_FUNCTION;

		try
		{
			char* GET_BUFFER;
			size_t GET_SIZE;
			uint8_t GET_IP_ADDRESS_MASK[4] = { 0,0,0,0 };

			CONVERT_TO_BYTES(inputIpAddress, GET_IP_ADDRESS_MASK);


			GET_SIZE = snprintf(NULL, 0, "%d.%d.%d.%d", GET_IP_ADDRESS_MASK[0], GET_IP_ADDRESS_MASK[1], GET_IP_ADDRESS_MASK[2], GET_IP_ADDRESS_MASK[3]);
			GET_BUFFER = (char*)malloc(GET_SIZE + 1);


			if (GET_BUFFER == NULL)
			{
				PRINT_ERROR_STATUS("[-] Ошибка!> В функции convertIpToString произошла ошибка конвертации IP байткода в STRING формат!");
				CALL_FUNCTION.WRITE_TO_LOG("В функции convertIpToString произошла ошибка конвертации IP байткода в STRING формат!");
				exit(-1);
			}
			else
			{
				snprintf(GET_BUFFER, GET_SIZE + 1, "%d.%d.%d.%d", GET_IP_ADDRESS_MASK[0], GET_IP_ADDRESS_MASK[1], GET_IP_ADDRESS_MASK[2], GET_IP_ADDRESS_MASK[3]);
				return (char*)GET_BUFFER;
			}
		}
		catch (...)
		{
			PRINT_ERROR_STATUS("[-] Ошибка!> В функции convertIpToString() произошла ошибка исключения!");
			CALL_FUNCTION.WRITE_TO_LOG("В функции convertIpToString() произошла ошибка исключения!");
			exit(-2);
		}
	}
};

class __BANNER
{
public:
	void* SHOW_BANNER()
	{
		system("clear");
		PRINT_TEXT_MESSAGE("###############################");
		PRINT_TEXT_MESSAGE("--------- LAN SCANNER ---------");
		PRINT_TEXT_MESSAGE("###############################");
		PRINT_TEXT_MESSAGE("1] Используйте: ./scanner --target <IP адрес/Маска сети> для запуска сканирования локальной сети!");
		PRINT_TEXT_MESSAGE("2] Используйте: ./scanner --single-target <IP адрес> для запуска сканирования отдельного IP адреса!");
		PRINT_TEXT_MESSAGE("3] Используйте: ./scanner --ignore <IP адрес> для создания исключений во время сканирования сети!");
		PRINT_TEXT_MESSAGE("Пример запуска: ./scanner --target 192.168.4.1/16 --ignore 192.168.4.125 192.168.4.14");
		PRINT_TEXT_MESSAGE("--------------------------------");
		return 0;
	}
};

void* PING_SCAN(void* arg)
{
	__ACTIONS START_SCANNER;

	try
	{
		START_SCANNER.START_PING_SCAN();
		return 0;
	}
	catch (...)
	{
		PRINT_ERROR_STATUS("[-] Ошибка!> В функции PING_SCAN() произошла ошибка исключения!");
		exit(-1);
	}
}

void* TELNET_SCAN(void* arg)
{
	__ACTIONS START_SCANNER;

	try
	{
		START_SCANNER.START_TELNET_SCAN();
		return 0;
	}
	catch (...)
	{
		PRINT_ERROR_STATUS("[-] Ошибка!> В функции TELNET_SCAN() произошла ошибка исключения!");
		exit(-1);
	}
}

void* SSH_SCAN(void* arg)
{
	__ACTIONS START_SCANNER;

	try
	{
		START_SCANNER.START_SSH_SCAN();
		return 0;
	}
	catch (...)
	{
		PRINT_ERROR_STATUS("[-] Ошибка!> В функции SSH_SCAN() произошла ошибка исключения!");
		exit(-1);
	}
}

void* START_ALL_SCANS(char* INPUT_IP_ADDRESS)
{
	__FUNCTIONS CALL_FUNCTION;

	GLOBAL_IP_ADDRESS = INPUT_IP_ADDRESS;

	try
	{
		pthread_create(&(LINUX_DAEMON_THREAD[0]), NULL, &TELNET_SCAN, NULL);
		pthread_create(&(LINUX_DAEMON_THREAD[1]), NULL, &SSH_SCAN, NULL);
		pthread_create(&(LINUX_DAEMON_THREAD[2]), NULL, &PING_SCAN, NULL);
		
		for (int GET_COUNTER = 0; GET_COUNTER < 3; GET_COUNTER++)
		{
			pthread_join(LINUX_DAEMON_THREAD[GET_COUNTER], NULL);
		}

		if (SCAN_STATUS == true)
		{
			PRINT_SUCCESS_STATUS(INPUT_IP_ADDRESS);
			return 0;
		}
		else
		{
			return 0;
		}
	}
	catch (...)
	{
		CALL_FUNCTION.WRITE_TO_LOG("[-] Ошибка!> В функции START_ALL_SCANS() произошла ошибка исключения!");
		PRINT_ERROR_STATUS("[-] Ошибка!> В функции START_ALL_SCANS() произошла ошибка исключения!");
		exit(-1);
	}
}

void* START_ALL_IP_SCANS(void* arg)
{
	__FUNCTIONS CALL_FUNCTION;

	try
	{
		START_ALL_SCANS(IP_TO_CHECK);
		return 0;
	}
	catch (...)
	{
		CALL_FUNCTION.WRITE_TO_LOG("[-] Ошибка!> В функции START_ALL_IP_SCANS() произошла ошибка исключения!");
		PRINT_ERROR_STATUS("[-] Ошибка!> В функции START_ALL_IP_SCANS() произошла ошибка исключения!");
		exit(-1);
	}
}


int main(int argc, char** argv)
{
	try
	{
		system("clear");
		setlocale(LC_ALL, "Russian");

		if (geteuid() != 0)
		{
			PRINT_ERROR_STATUS("[-] Ошибка! Чтобы использовать эту программу, запустите ее от имени пользователя 'root'!");
			exit(-1);
		}
		else
		{
			__FUNCTIONS CALL_FUNCTION;
			__ACTIONS CALL_SCANNER;
			__TOOLS CALL_TOOLS;
			__BANNER CALL_BANNER;

			uint32_t GET_IP_ADDRESS = 0;
			uint32_t GET_SUBNET_MASK_PREFIX = 0;
			uint32_t GET_IP_ADDRESS_COUNTER = 0;

			try
			{
				if (argc <= 1)
				{
					CALL_BANNER.SHOW_BANNER();
				}

				if (!strcmp(argv[1], "--help"))
				{
					CALL_BANNER.SHOW_BANNER();
				}
				else
				{
					if (!strcmp(argv[1], "--single-target"))
					{
						if (argv[2] == NULL)
						{
							PRINT_ERROR_STATUS("[-] Пожалуйста, укажите корректный IP адрес для сканирования!");
							CALL_FUNCTION.WRITE_TO_LOG("Попытка запуска утилиты с указанием неверного IP адреса!");
							exit(-2);
						}
						else
						{
							if (!strcmp(argv[2], "255.255.255.255"))
							{
								PRINT_ERROR_STATUS("[-] Пожалуйста, укажите корректный IP адрес для сканирования!");
								CALL_FUNCTION.WRITE_TO_LOG("Попытка запуска утилиты с указанием неверного IP адреса!");
								exit(-3);
							}
							else
							{
								if (!strcmp(argv[2], "0.0.0.0"))
								{
									PRINT_ERROR_STATUS("[-] Пожалуйста, укажите корректный IP адрес для сканирования!");
									CALL_FUNCTION.WRITE_TO_LOG("Попытка запуска утилиты с указанием неверного IP адреса!");
									exit(-4);
								}
								else
								{
									CALL_FUNCTION.WRITE_TO_LOG("Начато сканирование с параметром '--single-target'!");
									SCAN_STATUS = false;
									START_ALL_SCANS(argv[2]);
									return 0;
								}
							}
						}
					}
					else
					{
						if (!strcmp(argv[1], "--target"))
						{
							if (argv[3] == NULL)
							{
								if (argv[2] == NULL)
								{
									PRINT_ERROR_STATUS("[-] Пожалуйста, укажите корректный IP адрес для сканирования!");
									CALL_FUNCTION.WRITE_TO_LOG("Попытка запуска утилиты с указанием неверного IP адреса!");
									exit(-5);
								}
								else
								{
									if (CALL_TOOLS.SUBNET_MASK_PARSER(argv[2], &GET_IP_ADDRESS, &GET_SUBNET_MASK_PREFIX) < 0)
									{
										PRINT_ERROR_STATUS("[-] Ошибка! Формат ввода данных для сканирования должен быть в виде: X.X.X.X/S. Например: 192.168.5.2/24");
										CALL_FUNCTION.WRITE_TO_LOG("Попытка запуска утилиты с указанием неверного IP адреса!");
										exit(-6);
									}

									if (GET_SUBNET_MASK_PREFIX > 32)
									{
										PRINT_ERROR_STATUS("[-] Ошибка! Вы указали нестандартную маску сети!");
										CALL_FUNCTION.WRITE_TO_LOG("Попытка запуска утилиты с указанием неверной маски сети!");
										exit(-7);
									}

									GET_IP_ADDRESS_COUNTER = pow(2, 32 - GET_SUBNET_MASK_PREFIX);

									if (GET_IP_ADDRESS_COUNTER == 0)
									{
										PRINT_ERROR_STATUS("[-] Ошибка обработки маски сети! Пожалуйста, проверьте правильность вводимых данных!");
										CALL_FUNCTION.WRITE_TO_LOG("Попытка запуска утилиты с указанием неверных параметров!");
										exit(-8);
									}

									CALL_FUNCTION.WRITE_TO_LOG("Начато сканирование с параметром '--target'!");
									IP_ADDRESS_TABLE GET_TARGETS[GET_IP_ADDRESS_COUNTER];

									if (GET_IP_ADDRESS_COUNTER != 0)
									{
										for (int GET_COUNTER = 0; GET_COUNTER < GET_IP_ADDRESS_COUNTER; GET_COUNTER++)
										{
											GET_TARGETS[GET_COUNTER].INPUT_IP_ADDRESS = GET_IP_ADDRESS + htonl(GET_COUNTER);
											SCAN_STATUS = false;
											IP_TO_CHECK = CALL_TOOLS.CONVERT_IP_TO_STRING(GET_TARGETS[GET_COUNTER].INPUT_IP_ADDRESS);
											pthread_create(&(SCANNER_NETWORK_THREAD[GET_COUNTER]), NULL, &START_ALL_IP_SCANS, (void*) GET_COUNTER);
											pthread_join(SCANNER_NETWORK_THREAD[GET_COUNTER], NULL);
										}
										return 0;
									}
									else
									{
										IP_ADDRESS_TABLE GET_TARGETS;
										GET_TARGETS.INPUT_IP_ADDRESS = GET_IP_ADDRESS;
										return 0;
									}
								}
							}
							else
							{
								if (!strcmp(argv[3], "--ignore"))
								{
									if ((argv[2] == NULL) || (argv[4] == NULL))
									{
										PRINT_ERROR_STATUS("[-] Пожалуйста, укажите корректный IP адрес для сканирования или исключения!");
										CALL_FUNCTION.WRITE_TO_LOG("Попытка запуска утилиты с указанием неверного IP адреса!");
										exit(-9);
									}
									else
									{
										if (CALL_TOOLS.SUBNET_MASK_PARSER(argv[2], &GET_IP_ADDRESS, &GET_SUBNET_MASK_PREFIX) < 0)
										{
											PRINT_ERROR_STATUS("[-] Ошибка! Формат ввода данных для сканирования должен быть в виде: X.X.X.X/S. Например: 192.168.5.2/24");
											CALL_FUNCTION.WRITE_TO_LOG("Попытка запуска утилиты с указанием неверного IP адреса!");
											exit(-10);
										}

										if (GET_SUBNET_MASK_PREFIX > 32)
										{
											PRINT_ERROR_STATUS("[-] Ошибка! Вы указали нестандартную маску сети!");
											CALL_FUNCTION.WRITE_TO_LOG("Попытка запуска утилиты с указанием неверной маски сети!");
											exit(-11);
										}

										GET_IP_ADDRESS_COUNTER = pow(2, 32 - GET_SUBNET_MASK_PREFIX);

										if (GET_IP_ADDRESS_COUNTER == 0)
										{
											PRINT_ERROR_STATUS("[-] Ошибка обработки маски сети! Пожалуйста, проверьте правильность вводимых данных!");
											CALL_FUNCTION.WRITE_TO_LOG("Попытка запуска утилиты с указанием неверных параметров!");
											exit(-12);
										}

										CALL_FUNCTION.WRITE_TO_LOG("Начато сканирование с параметрами '--target' и '--ignore'!");
										IP_ADDRESS_TABLE GET_TARGETS[GET_IP_ADDRESS_COUNTER];

										if (GET_IP_ADDRESS_COUNTER != 0)
										{

											for (int GET_COUNTER = 0; GET_COUNTER < GET_IP_ADDRESS_COUNTER; GET_COUNTER++)
											{
												bool CHECK_IGNORE_LIST = false;

												GET_TARGETS[GET_COUNTER].INPUT_IP_ADDRESS = GET_IP_ADDRESS + htonl(GET_COUNTER);

												for (int GET_IGNORED_IPS = 4; argv[GET_IGNORED_IPS] != NULL; GET_IGNORED_IPS++)
												{
													if (!strcmp(argv[GET_IGNORED_IPS], CALL_TOOLS.CONVERT_IP_TO_STRING(GET_TARGETS[GET_COUNTER].INPUT_IP_ADDRESS)))
													{
														CHECK_IGNORE_LIST = true;
													}
												}
												if (CHECK_IGNORE_LIST == false)
												{
													SCAN_STATUS = false;
													IP_TO_CHECK = CALL_TOOLS.CONVERT_IP_TO_STRING(GET_TARGETS[GET_COUNTER].INPUT_IP_ADDRESS);
													pthread_create(&(SCANNER_NETWORK_THREAD[GET_COUNTER]), NULL, &START_ALL_IP_SCANS, NULL);
													pthread_join(SCANNER_NETWORK_THREAD[GET_COUNTER], NULL);
												}
											}
											return 0;
										}
										else
										{
											IP_ADDRESS_TABLE GET_TARGETS;
											GET_TARGETS.INPUT_IP_ADDRESS = GET_IP_ADDRESS;
											return 0;
										}
									}
								}
								else
								{
									PRINT_ERROR_STATUS("[-] Пожалуйста, вводите правильные параметры! Возможно, Вы хотели написать --ignore?");
									CALL_FUNCTION.WRITE_TO_LOG("Попытка запуска утилиты с указанием неверных параметров!");
									exit(-13);
								}
							}

						}
						else
						{
							PRINT_ERROR_STATUS("[-] Пожалуйста, вводите правильные параметры! Возможно, Вы хотели написать --target?");
							CALL_FUNCTION.WRITE_TO_LOG("Попытка запуска утилиты с указанием неверных параметров!");
							exit(-14);
						}
					}
				}
			}
			catch (...)
			{
				PRINT_ERROR_STATUS("[-] Ошибка!> В функции main() произошла ошибка исключения!");
				CALL_FUNCTION.WRITE_TO_LOG("В функции main() произошла ошибка исключения!");
				exit(-15);
			}
		}
	}
	catch (...)
	{
		PRINT_ERROR_STATUS("[-] Ошибка!> В функции main() произошла ошибка глобального исключения!");
		exit(-15);
	}
}