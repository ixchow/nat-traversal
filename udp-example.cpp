

/*
 * Simple UDP test code. Maybe a chat program? Seems fine.
 */


#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>

#include <iostream>
#include <cstring>
#include <cassert>

constexpr size_t MAX_DATA_SIZE = 65508; //<-- probably should set lower in general

int main(int argc, char **argv) {
	//create socket, make it datagram-flavored:
	int sockfd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);

	if (sockfd == -1) {
		std::cerr << "Error creating socket:\n" << strerror(errno) << std::endl;
		return 1;
	}

	//NOTE: binding not explicitly needed but will bind as a matter of style
	//  (and to make local firewall settings clearer)

	{ //bind socket to local address:
		struct sockaddr_in addr;
		memset(&addr, '\0', sizeof(addr));
		addr.sin_family = AF_INET;
		addr.sin_port = htons(15221);
		addr.sin_addr.s_addr = INADDR_ANY;

		int ret = bind(sockfd, reinterpret_cast< const sockaddr * >(&addr), sizeof(addr));
		if (ret != 0) {
			std::cerr << "Error binding socket:\n" << strerror(errno) << std::endl;
			return 1;
		}
	}

	//(Should now be able to sendto and recvfrom on the socket.)

	if (argc >= 2) {
		//send message(s) to specified place before waiting for messages

		//TODO: consider getaddrinfo(!)
		struct sockaddr_in dest_addr;
		memset(&dest_addr, '\0', sizeof(dest_addr));
		dest_addr.sin_family = AF_INET;
		dest_addr.sin_port = htons(15221);
		dest_addr.sin_addr.s_addr = inet_addr(argv[1]);

		if (dest_addr.sin_addr.s_addr == INADDR_NONE) {
			std::cout << "Invalid ip address: '" << argv[1] << "'" << std::endl;
			return 1;
		}

		for (int a = 2; a < argc; ++a) {
			std::string buf = argv[a];
			ssize_t sent = sendto(sockfd, buf.data(), buf.size(), 0, reinterpret_cast< const sockaddr * >(&dest_addr), sizeof(dest_addr));

			if (sent < 0) {
				assert(sent == -1);
				std::cout << "Error sending message '" << buf << "':\n" << strerror(errno) << std::endl;
				//NOTE: continue trying to send *other* messages
			} else { assert((size_t)sent == buf.size());
				std::cout << "Sent message '" << buf << "'." << std::endl;
			}
		}

	}

	std::cout << "Socket bound and stuff." << std::endl;
	while (true) {
		struct sockaddr_in src_addr;
		memset(&src_addr, '\0', sizeof(src_addr)); //<-- not really needed, I'd expect
		socklen_t addrlen = sizeof(src_addr);

		static uint8_t buf[MAX_DATA_SIZE];

		std::cout << "Waiting for message..." << std::endl;
		ssize_t got = recvfrom(sockfd, &buf, sizeof(buf), 0, reinterpret_cast< sockaddr * >(&src_addr), &addrlen);

		if (got < 0) {
			assert(got == -1); //other negative results not specified behavior
			//message... not received?
			std::cerr << "Error recvfrom'ing:\n" << strerror(errno) << std::endl;
			sleep(1);
		} else { assert(got >= 0); //only remaining option
			//message received!
			if ((size_t)got > sizeof(buf)) {
				got = sizeof(buf);
				std::cout << "NOTE: some bytes discarded." << std::endl;
			}
			std::cout << "Got message from " << inet_ntoa(src_addr.sin_addr) << ":" << ntohs(src_addr.sin_port) << ":\n" << std::string(buf, buf + got) << std::endl;
		}
	}

}
