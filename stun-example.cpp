

/*
 * Simple UDP / STUN test code. Figures out own info and prints it out.
 */


#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <netdb.h>

#include <iostream>
#include <cstring>
#include <cassert>
#include <random>
#include <sstream>

constexpr size_t MAX_DATA_SIZE = 65508; //<-- probably should set lower in general

template< typename T >
std::string binary(T val, uint32_t bits) {
	std::string ret;
	ret.reserve(bits);
	assert(bits >= 8*sizeof(val) || (val >> bits) == 0);
	while (bits != 0) {
		bits -= 1;
		if (val & (1 << bits)) ret += '1';
		else ret += '0';
	}
	return ret;
}

template< typename T >
std::string hex(T val, uint32_t digits) {
	std::string ret;
	ret.reserve(digits);
	assert(digits >= 2*sizeof(val) || (val >> (4*digits)) == 0);
	while (digits != 0) {
		digits -= 1;
		ret += "0123456789abcdef"[(val >> (4*digits)) & 0xf];
	}
	return ret;
}

void dump_stun_message(std::string const &message) {
	if (message.size() < 20) {
		std::cout << "(INVALID message: header is too small.)" << std::endl;
		return;
	}
	std::istringstream ss(message);

	{ //-------- header: type ------
		uint16_t type;
		if (!ss.read(reinterpret_cast< char * >(&type), 2)) {
			std::cout << "Error: ran out of bytes reading type." << std::endl;
			return;
		}
		type = ntohs(type);
		std::cout << "Should be 00: 0b" << ((type >> 15) & 0x1) << ((type >> 14) & 0x1) << std::endl;
		// 8 gets shifted right by 7
		// 4 gets shifted right by 4
		uint8_t cls = ((type & 0x0100) >> 7) | ((type & 0x0010) >> 4);
		// 13-9 get shifted right by 2 -->0x3e00
		// 7-5 get shifted right by 1 --> 0x00e0
		// 3-0 aren't shifted --> 0x000f
		uint8_t method = ((type & 0x3e00) >> 2) | ((type & 0x00e0) >> 1) | (type & 0x000f);
	
		std::cout << "Class: 0b" << binary(cls, 2) << "\n";
		std::cout << "Method: 0b" << binary(method, 12) << "\n";
	}

	{ //-------- header: length ------
		uint16_t length;
		if (!ss.read(reinterpret_cast< char * >(&length), 2)) {
			std::cout << "Error: ran out of bytes reading length." << std::endl;
			return;
		}
		length = ntohs(length);
		std::cout << "Length: " << length;

		if (length + 20U != message.size()) std::cout << " (INVALID! Length should be " << int32_t(message.size()) - 20 << ")";
		std::cout << "\n";
	}

	{ //-------- header: cookie ------
		uint32_t cookie;
		if (!ss.read(reinterpret_cast< char * >(&cookie), 4)) {
			std::cout << "Error: ran out of bytes reading cookie." << std::endl;
			return;
		}
		cookie = ntohl(cookie);
		std::cout << "Cookie: 0x" << hex(cookie, 8);
		if (cookie != 0x2112A442) std::cout << " (INVALID! must be 0x2112A442)";
		std::cout << "\n";
	}

	{ //-------- header: ID ------
		uint32_t id[3];
		static_assert(sizeof(id) == 3*4, "sizeof static array gives size of array in bytes, right?");
		if (!ss.read(reinterpret_cast< char * >(id), sizeof(id))) {
			std::cout << "Error: ran out of bytes reading id." << std::endl;
			return;
		}
		std::cout << "Transaction ID: 0x" << hex(id[0], 8) << " " << hex(id[1], 8) << " " << hex(id[2], 8) << "\n";
	}

	//------ attributes ------
	while (ss.peek() != std::istringstream::traits_type::eof()) {
		//read attribute:
		uint16_t type;
		if (!ss.read(reinterpret_cast< char * >(&type), 2)) {
			std::cout << "Error: ran out of bytes reading type." << std::endl;
			return;
		}
		type = ntohs(type);
		std::cout << "Type: 0x" << hex(type, 4);
		if      (type == 0x0000) std::cout << " (Reserved)";
		else if (type == 0x0001) std::cout << " MAPPED_ADDRESS";
		else if (type == 0x0002) std::cout << " (Reserved; was RESPONSE-ADDRESS)";
		else if (type == 0x0003) std::cout << " (Reserved; was CHANGE-ADDRESS)";
		else if (type == 0x0004) std::cout << " (Reserved; was SOURCE-ADDRESS)";
		else if (type == 0x0005) std::cout << " (Reserved; was CHANGED-ADDRESS)";
		else if (type == 0x0006) std::cout << " USERNAME";
		else if (type == 0x0007) std::cout << " (Reserved; was PASSWORD)";
		else if (type == 0x0008) std::cout << " MESSAGE-INTEGRITY";
		else if (type == 0x0009) std::cout << " ERROR-CODE";
		else if (type == 0x000a) std::cout << " UNKNOWN-ATTRIBUTES";
		else if (type == 0x000b) std::cout << " (Reserved; was REFLECTED-FROM)";
		else if (type == 0x0014) std::cout << " REALM";
		else if (type == 0x0015) std::cout << " NONCE";
		else if (type == 0x0020) std::cout << " XOR-MAPPED-ADDRESS";
		else if (type == 0x8022) std::cout << " SOFTWARE";
		else if (type == 0x8023) std::cout << " ALTERNATE-SERVER";
		else if (type == 0x8028) std::cout << " FINGERPRINT";
		else if (type <= 0x7FFF) std::cout << " (Unknown; Comprehension-required)";
		else std::cout << " (Unknown; Comprehension-optional)";
		std::cout << "\n";

		uint16_t length;
		if (!ss.read(reinterpret_cast< char * >(&length), 2)) {
			std::cout << "Error: ran out of bytes reading length." << std::endl;
			return;
		}
		length = ntohs(length);
		std::cout << "Length: " << length << "\n";

		std::string value;
		for (uint32_t i = 0; i < length; ++i) {
			char c;
			if (!ss.read(&c, 1)) {
				std::cout << "Error: ran out of bytes reading value." << std::endl;
				return;
			}
			value += c;
		}
		std::cout << "Value: '" << value << "'\n";

		std::string padding;
		for (uint32_t i = length; i % 4; ++i) {
			char c;
			if (!ss.read(&c, 1)) {
				std::cout << "Error: ran out of bytes reading padding." << std::endl;
				return;
			}
			padding += c;
		}
		std::cout << "Padding: '" << padding << "' (" << padding.size() << " bytes)";
		if (padding.size() >= 4) std::cout << " (INVALID: padding should be 0-3 bytes)";
		if ((padding.size() + value.size()) % 4) std::cout << " (INVALID: padding + value should be multiple of four)";
		std::cout << "\n";


		if (type == 0x0020) {
			assert(value.size() == length);
			if (value.size() == 8) {
				//ipv4 version
				std::cout << "XOR-MAPPED-ADDRESS (ipv4):\n";
				uint8_t zeros = value[0];
				std::cout << " zero padding: 0x" << hex(zeros, 2) << "\n";
				uint8_t family = value[1];
				std::cout << " family: 0x" << hex(family, 2);
				if (family != 0x01) std::cout << " (INVALID: expecting 0x01 for ipv4)";
				std::cout << "\n";

				uint16_t port = (uint16_t(value[2]) << 8) | uint16_t(value[3]);
				//de-xor port:
				port = port ^ (0x2112A442 >> 16);
				std::cout << " port: " << port << "\n";

				uint32_t addr = (uint32_t(uint8_t(value[4])) << 24) | (uint32_t(uint8_t(value[5])) << 16) | (uint32_t(uint8_t(value[6])) << 8) | uint32_t(uint8_t(value[7]));
				//de-xor addr:
				addr = addr ^ 0x2112A442;

				struct in_addr ia;
				ia.s_addr = htonl(addr);
				std::cout << " addr: 0x" << hex(addr, 8) << " == " <<  inet_ntoa(ia) << "\n";

			} else if (value.size() == 20) {
				//ipv6 version

				//.... I guess not?
			} else {
				std::cout << "XOR-MAPPED-ADDRESS of invalid length!\n";
			}
		}
	}
	std::cout.flush();
}


//Parse a STUN server response to find mapped host+port:
// fills in ipv4 address info + returns
// throws on error / invalid message / wrong transaction
struct sockaddr_in get_mapped_address(std::string const &message, uint32_t (&id_)[3]) {
	std::istringstream ss(message);

	{ //-------- header: type ------
		uint16_t type;
		if (!ss.read(reinterpret_cast< char * >(&type), 2)) {
			throw std::runtime_error("Error: ran out of bytes reading type.");
		}
		type = ntohs(type);
		if (type != 0x0101) {
			throw std::runtime_error("Error: message type was " + hex(type, 4) = ", expecting 0x0101.");
		}
	}

	{ //-------- header: length ------
		uint16_t length;
		if (!ss.read(reinterpret_cast< char * >(&length), 2)) {
			throw std::runtime_error("Error: ran out of bytes reading length.");
		}
		length = ntohs(length);
		if (length + 20U != message.size()) {
			throw std::runtime_error("Error: length doesn't match message length.");
		}
	}

	{ //-------- header: cookie ------
		uint32_t cookie;
		if (!ss.read(reinterpret_cast< char * >(&cookie), 4)) {
			throw std::runtime_error("Error: ran out of bytes reading cookie."); //<-- shouldn't happen because of length check above(!)
		}
		cookie = ntohl(cookie);
		if (cookie != 0x2112A442) {
			throw std::runtime_error("Error: expected cookie of 0x2112A442, got 0x" + hex(cookie, 8) + ".");
		}
	}

	{ //-------- header: ID ------
		uint32_t id[3];
		static_assert(sizeof(id) == 3*4, "sizeof static array gives size of array in bytes, right?");
		if (!ss.read(reinterpret_cast< char * >(id), sizeof(id))) {
			throw std::runtime_error("Error: ran out of bytes reading transaction id."); //<-- shouldn't happen because of length check above(!)
		}
		if (id[0] != id_[0] || id[1] != id_[1] || id[2] != id_[2]) {
			throw std::runtime_error("Error: transaction id mis-match.");
		}
	}

	//------ attributes ------
	while (ss.peek() != std::istringstream::traits_type::eof()) {
		//read attribute:
		uint16_t type;
		if (!ss.read(reinterpret_cast< char * >(&type), 2)) {
			throw std::runtime_error("Error: ran out of bytes reading attribute type.");
		}
		type = ntohs(type);

		uint16_t length;
		if (!ss.read(reinterpret_cast< char * >(&length), 2)) {
			throw std::runtime_error("Error: ran out of bytes reading attribute length.");
		}
		length = ntohs(length);

		std::string value;
		for (uint32_t i = 0; i < length; ++i) {
			char c;
			if (!ss.read(&c, 1)) {
				throw std::runtime_error("Error: ran out of bytes reading attribute value.");
			}
			value += c;
		}

		std::string padding;
		for (uint32_t i = length; i % 4; ++i) {
			char c;
			if (!ss.read(&c, 1)) {
				throw std::runtime_error("Error: ran out of bytes reading attribute padding.");
			}
			padding += c;
		}
		assert(padding.size() < 4);
		assert((padding.size() + value.size()) % 4 == 0);


		if (type == 0x0020) {
			assert(value.size() == length);
			if (value.size() == 8) {
				//ipv4 version
				uint8_t zeros = value[0];
				if (zeros != 0) {
					throw std::runtime_error("Error: XOR-MAPPED-ADDRESS has 0x" + hex(zeros,2) + " instead of zeros.");
				}
				uint8_t family = value[1];
				if (family != 0x01) {
					throw std::runtime_error("Error: XOR-MAPPED-ADDRESS has family 0x" + hex(family,2) + " instead of 0x01 (ipv4).");
				}

				uint16_t port = (uint16_t(value[2]) << 8) | uint16_t(value[3]);
				port = port ^ (0x2112A442 >> 16);

				uint32_t addr = (uint32_t(uint8_t(value[4])) << 24) | (uint32_t(uint8_t(value[5])) << 16) | (uint32_t(uint8_t(value[6])) << 8) | uint32_t(uint8_t(value[7]));
				//de-xor addr:
				addr = addr ^ 0x2112A442;

				struct sockaddr_in ret;
				memset(&ret, '\0', sizeof(ret));
				ret.sin_family = AF_INET;
				ret.sin_port = htons(port);
				ret.sin_addr.s_addr = htonl(addr);

				return ret;
			} else if (value.size() == 20) {
				//ipv6 version
				throw std::runtime_error("Error: XOR-MAPPED-ADDRESS for ipv6 (wanted ipv4).");
			} else {
				throw std::runtime_error("Error: XOR-MAPPED-ADDRESS of invalid length.");
			}
		}
	}
	throw std::runtime_error("Error: no XOR-MAPPED-ADDRESS attribute.");
}


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
		addr.sin_port = htons(15221); //TODO: don't actually care about port (will discover from server)
		addr.sin_addr.s_addr = INADDR_ANY;

		int ret = bind(sockfd, reinterpret_cast< const sockaddr * >(&addr), sizeof(addr));
		if (ret != 0) {
			std::cerr << "Error binding socket:\n" << strerror(errno) << "\n (will continue anyway, with what I can only assume will be an different port number.)" << std::endl;
		}
	}

	bool have_self_addr = false;
	struct sockaddr_in self_addr;

	{ //use STUN protocol to figure out public host/port.
		std::string node = "stun.stunprotocol.org"; //<-- should be configurable
		struct addrinfo *res = nullptr;

		struct addrinfo hints;
		memset(&hints, '\0', sizeof(hints));

		hints.ai_family = AF_INET;
		hints.ai_socktype = SOCK_DGRAM;
		hints.ai_protocol = IPPROTO_UDP; //or '0' for "don't care"

		int ret = getaddrinfo(node.c_str(), "3478", &hints, &res);

		if (ret != 0) {
			std::cerr << "Error from getaddrinfo:\n" << gai_strerror(ret) << std::endl;
			return 1;
		}


		//loop through all of the returned options:
		for (struct addrinfo *option = res; option; option = option->ai_next) {
			assert(option->ai_family == AF_INET);
			assert(option->ai_socktype == SOCK_DGRAM);
			assert(option->ai_protocol == IPPROTO_UDP);
			assert(option->ai_addrlen == sizeof(struct sockaddr_in));
			const struct sockaddr_in &stun_addr = *reinterpret_cast< const struct sockaddr_in * >(option->ai_addr);
			std::cout << "Server option " << inet_ntoa(stun_addr.sin_addr) << ":" << ntohs(stun_addr.sin_port) << std::endl;

			//Create a (random) transaction ID:
			uint32_t id[3];
			static std::random_device rd; //NOTE: watch out for determinism here? (e.g., could xor microseconds from clock)
			id[0] = rd();
			id[1] = rd();
			id[2] = rd();


			//Build STUN message:

			std::string message;

			{ //add 'SOFTWARE' attribute to body:
				std::string value = "TCHOW STUN Test";
				uint16_t type = htons(0x8022);
				uint16_t length = htons(value.size());
				message += std::string(reinterpret_cast< const char * >(&type), 2);
				message += std::string(reinterpret_cast< const char * >(&length), 2);
				message += value;
				while (message.size() % 4) message += '\0';
			}

			//add header to message:
			struct STUNHeader {
				uint16_t type;
				uint16_t length;
				uint32_t cookie;
				uint32_t id[3];
			} __attribute__((packed));
			STUNHeader header;
			static_assert( sizeof(header) == 20, "header is packed.");

			header.type = htons(0x0001); //class 'request' (b00) method 'Binding' (b00..01)
			header.length = htons(message.size());
			header.cookie = htonl(0x2112A442);
			header.id[0] = id[0];
			header.id[1] = id[1];
			header.id[2] = id[2];

			message = std::string(reinterpret_cast< const char * >(&header), sizeof(header)) + message;

			//STUN request message is.... ready?

			ssize_t sent = sendto(sockfd, message.data(), message.size(), 0, reinterpret_cast< const sockaddr * >(&stun_addr), sizeof(stun_addr));

			if (sent < 0) {
				assert(sent == -1);
				std::cout << "Error sending message '" << message << "':\n" << strerror(errno) << std::endl;
				//NOTE: continue trying to send *other* messages
			} else { assert((size_t)sent == message.size());
				std::cout << "Sent message:\n";
				dump_stun_message(message);
			}

			//wait for response:
			while (true) { //<-- should be finite number of retries
				//TODO: use select() so can wait with timeout
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
					std::cout << "Got message from " << inet_ntoa(src_addr.sin_addr) << ":" << ntohs(src_addr.sin_port) << ":\n";
					dump_stun_message(std::string(buf, buf + got));

					try {
						self_addr = get_mapped_address(std::string(buf, buf + got), id);
						have_self_addr = true;
						break;
					} catch (std::exception &e) {
						std::cout << "Error parsing message: " << e.what() << std::endl;
						//TODO: retry? next server?
					}
				}
			}

			if (have_self_addr) break; //no need to keep asking
		}

		freeaddrinfo(res);

	}
	if (have_self_addr) {
		std::cout << "Local Address: " << inet_ntoa(self_addr.sin_addr) << ":" << ntohs(self_addr.sin_port) << std::endl;
	} else {
		std::cout << "Error: Was unable to determine local address." << std::endl;
		return 1;
	}

	//(Should now be able to sendto and recvfrom on the socket.)

	if (argc >= 3) {
		//send message(s) to specified place before waiting for messages

		//TODO: consider getaddrinfo(!)
		struct sockaddr_in dest_addr;
		memset(&dest_addr, '\0', sizeof(dest_addr));
		dest_addr.sin_family = AF_INET;
		dest_addr.sin_port = htons(atoi(argv[2]));
		dest_addr.sin_addr.s_addr = inet_addr(argv[1]);

		if (dest_addr.sin_addr.s_addr == INADDR_NONE) {
			std::cout << "Invalid ip address: '" << argv[1] << "'" << std::endl;
			return 1;
		}

		std::cout << "Sending some messages to " << inet_ntoa(dest_addr.sin_addr) << ":" << ntohs(dest_addr.sin_port) << " :" << std::endl;

		for (int a = 3; a < argc; ++a) {
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
