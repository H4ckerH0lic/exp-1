from flask import Flask, render_template
import scapy.all as scapy

app = Flask(__name__)

@app.route('/')
def index():
    return "Welcome to Network Scanner!"

@app.route('/scan')
def scan_network():
    target_ip = "192.168.1.103/24"
    scan_result = scan(target_ip)
    return render_template('scan_result.html', result_list=scan_result)

def scan(ip):
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast/arp_request
    answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]

    client_list=[]
    for element in answered_list:
        client_dict= {"IP":element[1].psrc,"Mac":element[1].hwsrc}
        client_list.append(client_dict)
    return client_list

if __name__ == "__main__":
    app.run(debug=True)
