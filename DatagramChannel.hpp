#pragma once

/*
 * DatagramChannel is an *unreliable*, *out-of-order* transmission channel.
 * It uses STUN to connect (even through NATs).
 *
 * Workflow:
 *  (1) "host" player sees their port/ip in connect screen
 *  (2) communicates this to "joining" players out-of-band
 *  (3) connection done!
 *
 * General channel construction:
 *  (1) "reserve" an address (initiates STUN request, gets own info)
 *  (2) "connect" address to endpoint (gets others' info)
 *  (3) [alt] "listen" for connections from others
 *
 */


struct DatagramChannel {
	//Construct channel given remote address:
	DatagramChannel(std::string address, uint16_t port = 0);

	//Utility stuff:
	static std::string what_is_my_address();

};
