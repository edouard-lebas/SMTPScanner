import socket
import time
from datetime import datetime
from multiprocessing.pool import ThreadPool as Pool
import smtplib
import nmap

class SMTPScanner:
    def __init__(self, ip_list):
        self.pool_size = 20
        self.pool = Pool(self.pool_size)
        self.ip_list = ip_list
        now = datetime.now()
        dt_string = now.strftime("%d-%m-%Y_%H-%M-%S")
        filename = "SMTPScanner_" + dt_string + ".csv"
        self.file = open(filename, "w")
        self.nm = nmap.PortScanner()

    def __del__(self):
        self.file.close()

    def test_nmap(self, host, port):
        try:
            self.nm.scan(host, port)
            self.nm.scaninfo()
        except Exception as e:
            print (str(e))

    def test_smtp(self, host, port):
        server = smtplib.SMTP()
        try:
            print("HOST > " + str(host))
            co = server.connect(host)
            print("CO > " + str(co))
            he = server.helo()
            print("HE > " + str(he))
            self.file.write(str(host + "," + str(port) + ",OPEN\n"))
            print(host + ":" + str(port) + " > OPEN")
        except Exception as e:
            self.file.write(str(host + "," + str(port) + ",CLOSE\n"))
            print(host + ":" + str(port) + " > CLOSE : " + str(e))

    def connect_socket(self, host, port):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(2)
        try:
            con = s.connect((host, port))
            self.file.write(str(host + "," + str(port) + ",OPEN\n"))
            print(host + ":" + str(port) + " > OPEN")
        except Exception as e:
            self.file.write(str(host + "," + str(port) + ",CLOSE\n"))
            print(host + ":" + str(port) + " > CLOSE : " + str(e))
            pass
        finally:
            s.close()

    def run(self):
        for i in self.ip_list:
            self.pool.apply_async(self.test_nmap, (str(i), "25",))
        self.pool.close()
        self.pool.join()

    def display(self):
        for host in self.nm.all_hosts():
            print('----------------------------------------------------')
            print('Host : %s (%s)' % (host, self.nm[host].hostname()))
            print('State : %s' % self.nm[host].state())

            for proto in self.nm[host].all_protocols():
                print('----------')
                print('Protocol : %s' % proto)

                lport = self.nm[host][proto].keys()
                lport.sort()
                for port in lport:
                    print('port : %s\tstate : %s' % (port, self.nm[host][proto][port]['state']))


if __name__ == "__main__":
    print("[START]")
    start_time = time.time()
    file_ip = open("ip.txt", "r")
    lines_ip = file_ip.readlines()
    all_ip = []
    for l in lines_ip:
        all_ip.append(l.strip())
    ts = SMTPScanner(all_ip)
    ts.run()
    ts.display()
    print("--- %s seconds ---" % (time.time() - start_time))
    print("[STOP]")
