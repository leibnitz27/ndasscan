/* Horrible hacky code to scan network for NDAS helo packets, and infer keys from them 
 * Requires:
 *   libpcap
 *
 * 2.0
 *
 * link against : wpcap.lib
 *
 * 2014/04/27 - Rewrite from v 0.6.   Now IOCELL have open sourced the XIMETA NDAS code, we no longer need to find the
 * key generation routines in the distributed binaries - we include the XIMETA code directly!  
 * 
 * http://www.iocellnetworks.com/neo/index.php/press/item/ndas-source-code-released
 *
 * This means there is no need for any more updates for new XIMETA binaries! Hurrah!
 *
 */
#include <set>
#include <map>
#include <vector>
#include <string>
#include <iostream>
#include <sstream>
#define WPCAP 
#define HAVE_REMOTE
#include "pcap.h"
#include <windows.h>
#include <conio.h> 
#include "ndas/ndasid.h"

#define CAPTURE_TIME 5000

// Guesstimate as to the max size of an ndas helo.
#define NDAS_HELO_MAX 100

#define VERSION "2.0"

unsigned char ndas_helo_prefix_ref[] = {
	0x80, 0x12, 0x27, 0x12, 0x27, 0x11
};

struct mac
{
	mac(const unsigned char x[6]){
		memcpy(addr, x, 6 * sizeof(unsigned char));
	}
	mac(const std::string & s)
	{
		std::stringstream ss;
		ss << s;
		unsigned char a,b;
		for (int i=0;i<6;++i)
		{
			if (i) ss >> a;
			ss >> a >> b;
			addr[i]  = ((a>='0'&&a<='9')?(a-'0'):((a|0x20)+10-'a'))<<4;
			addr[i] |= ((b>='0'&&b<='9')?(b-'0'):((b|0x20)+10-'a'));
		}
	}
	bool operator <(const mac & other) const
	{
		for (int x=0;x<6;++x)
		{
			if (addr[x] < other.addr[x]) return true;
			if (addr[x] > other.addr[x]) return false;
		}
		return false;
	}
	operator std::string () const
	{
		std::string s;
		for (int x=0;x<6;++x)
		{
			int i;
			if (x) s += ":";
			s += (i = ((addr[x] & 0xf0) >> 4)) < 10 ? ('0' + i) : ('A' - 10 + i);
			s += (i = (addr[x] & 0x0f)) < 10 ? ('0' + i) : ('A' - 10 + i);
		}
		return s;
	}
	unsigned char addr[6];
};

struct ndas_hello_packet_eth {
	unsigned char dest_mac[6]; // will be broadcast
	unsigned char source_mac[6];
	unsigned char proto[2]; // 88ad
	unsigned char data[sizeof(ndas_helo_prefix_ref)];
};


// hardly worth using boost...
class timer
{
	static double tickfreq;
	double m_start;
	
	double get_ticks()
	{
		LARGE_INTEGER x;
		QueryPerformanceCounter(&x);
		return static_cast<double>(x.QuadPart);
	}
public:
	timer() {
		m_start = get_ticks();
	}
	double elapsed_millis()
	{
		return (get_ticks() - m_start) / tickfreq;
	}
};

double get_tick_f() {
	LARGE_INTEGER x;
	QueryPerformanceFrequency(&x);
	return static_cast<double>(x.QuadPart) / 1000;
}

double timer::tickfreq = get_tick_f();

class pcap_guard
{
	pcap_t * m_handle;
public:
	pcap_guard(pcap_t * handle) : m_handle(handle) {}
	~pcap_guard() { pcap_close(m_handle); }
private:
	pcap_guard(const pcap_guard & other);
	pcap_guard & operator=(const pcap_guard & other);
};

class pcap_devs_guard
{
	pcap_if_t * m_alldevs;
public:
	pcap_devs_guard(pcap_if_t *alldevs) : m_alldevs(alldevs) {}
	~pcap_devs_guard() { pcap_freealldevs(m_alldevs); }
private:
	pcap_devs_guard(const pcap_guard & other);
	pcap_devs_guard & operator=(const pcap_guard & other);
};


int listen_ndas_helo(std::set<mac> & seen_macs)
{

	pcap_if_t *alldevs;
	pcap_if_t *d;
	int i=0;
	pcap_t *adhandle;
	char errbuf[PCAP_ERRBUF_SIZE];
    
    /* Retrieve the device list on the local machine */
    if (pcap_findalldevs_ex(PCAP_SRC_IF_STRING, NULL, &alldevs, errbuf) == -1)
    {
		std::cout << "Error in pcap_findalldevs: " << errbuf << "\n";
        return -1;
    }
	pcap_devs_guard all_devguard(alldevs);
    
    /* Print the list */
    for(d = alldevs; d != NULL; d=d->next)
    {
		std::cout << "Scanning for NDAS devices from " << d->name << "\n";

		if (!d->addresses || !d->addresses->addr)
		{
			std::cout << "Adapter not connected, skipping\n";
			continue;
		}

		if ( (adhandle= pcap_open(d->name,          // name of the device
								  1024,            // portion of the packet to capture
								  PCAP_OPENFLAG_PROMISCUOUS,    // promiscuous mode
								  100,             // read timeout
								  NULL,             // authentication on the remote machine
								  errbuf            // error buffer
								  ) ) == NULL)
		{
			std::cout << "Unable to open the adapter. " << d->name << " is not supported by WinPcap\n";
			continue;
		}
		pcap_guard devguard(adhandle);

		int linktype = pcap_datalink(adhandle);
		if (linktype != DLT_EN10MB)
		{
			if (linktype == DLT_IEEE802_11)
			{
				// I'm too lazy to add interpretation for 802.11 frames....
				std::cout << d->name << ": 802.11 device not supported - skipping." << std::endl;
			} 
			else
			{
				std::cout << d->name << ": Interface type not supported - skipping." << std::endl;
			}
			continue;
		}

		struct bpf_program fcode;
		
		
		if (pcap_compile(adhandle, &fcode, "ether proto 0x88ad and ether broadcast", 1, 0xffffff) < 0 ||
			pcap_setfilter(adhandle, &fcode)<0 )
		{
			std::cout << "Odd pcap error - can't continue.\n";
			return -1;
		}
		

		const u_char *pkt_data;
		struct pcap_pkthdr *header;
		/* Retrieve the packets */
		int res;

		timer tmr;
		// Capture for (roughly) CAPTURE_TIME milliseconds 
		double dt;
		while((dt = tmr.elapsed_millis()) < CAPTURE_TIME && (res = pcap_next_ex( adhandle, &header, &pkt_data)) >= 0 ){

			if(res == 0)
			{
				/* Timeout elapsed */
				continue;
			}
	        
			if (sizeof(ndas_hello_packet_eth) >= header->caplen)
			{
				std::cout << "Packet seen with correct frame id, but too small." << std::endl;
				continue;
			}

			const ndas_hello_packet_eth * pplkt = reinterpret_cast<const ndas_hello_packet_eth*>(pkt_data);
			
			if (pplkt->proto[0] != 0x88 || pplkt->proto[1] != 0xad)
			{
				std::cout << "Wrong header." << std::endl;
				continue;
			}
			if (memcmp(pplkt->data, ndas_helo_prefix_ref, sizeof(ndas_helo_prefix_ref)))
			{
				std::cout << "Packet seen, but didn't match HELO." << std::endl;
				continue;
			}

			std::cout << "HELO seen, len " << header->caplen << std::endl;
			seen_macs.insert(mac(pplkt->source_mac));
		}
	    
		if(res == -1)
		{
			std::cout << "Error reading the packets: " << pcap_geterr(adhandle) << std::endl;
			return -1;
		}
		else
		{
			std::cout << "Listen period expired." << std::endl;
		}
	}

    return 0;
}

void print_ndas_info(const mac & m)
{
	char szID[22];
	char szKey[6];
	memset(szID, 0, sizeof(szID));
	memset(szKey, 0, sizeof(szKey));
	unsigned long magic1[] = { 0x2f563245, 0x53384aec, 0xeb0f4e1e, 0x0c1502733 };
	unsigned long magic2[] = { 0xffff01cd };

	int hr = NdasIdDeviceToStringExA((const NDAS_DEVICE_ID*)m.addr, szID, szKey, (NDASID_EXT_KEY*) magic1, (NDASID_EXT_DATA*) magic2);
	if (!hr) 
	{
		std::cout << "Generation of NDAS id for MAC " << static_cast<std::string>(m) << " failed.\n";
		return;
	}
	std::cout << "MAC       : " << static_cast<std::string>(m) << "\n" << 
				 "NDAS ID   : " << szID << "\n" << 
				 "Write Key : " << szKey << "\n";
	if (!NdasIdValidateA(szID, szKey))
		std::cout << "WARNING: Verify returns: " << NdasIdValidateA(szID, szKey) << "\n";

}

int main(int argc, char *argv[])
{
	std::cout << "NDASSCAN " VERSION << " - http://www.benf.org/other/rapsody \n--------" << std::endl;
	std::set<mac> seen_macs;
	char * forced_mac = argc > 1 ? argv[1] : NULL;
	if (forced_mac != NULL)
	{
		std::cout << "Forcing MAC [" << forced_mac << "]" << std::endl;
		seen_macs.insert(mac(forced_mac));
	}
	else if (listen_ndas_helo(seen_macs))
	{
		std::cout << "Packet sniffing failed.\n";
		exit(1);
	}

	if (seen_macs.size() == 0) 
	{
		std::cout << "--------\nNo NDAS HELO packets received - supply a MAC as argument to force a device ID." << std::endl;
	}
	for (std::set<mac>::const_iterator sit = seen_macs.begin(); sit != seen_macs.end(); ++sit)
	{
		std::cout << "--------[Displaying NDAS Info]--------" << std::endl;
		try 
		{
			print_ndas_info(*sit);
		} 
		catch (...)
		{
			std::cout << "**Error while calling into NDASUSER.DLL**" << std::endl;
		}
	}


	return 0;
}

