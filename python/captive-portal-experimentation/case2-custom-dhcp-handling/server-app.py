from flask import Flask, render_template, request
from scapy.all import IP, UDP, sendp, ICMP, Ether
from python_arptable import get_arp_table
app = Flask(__name__)


credentials = {
    'user1': 'password1',
    'user2': 'password2',
    'user3': 'password3'
}

def send_packet():
    paquet_validation = Ether(dst=str(client_mac)) / IP(dst=request.remote_addr,src='1.2.3.4') / ICMP()
    sendp(paquet_validation,iface='eth0') 
    return "Packet sended"

def mac_from_ip(ip):
    arp_table = get_arp_table()

    for entry in arp_table:
        if entry['IP address'] == ip:
            return entry['HW address']
    return None

@app.route('/')
def index():
    return render_template('index.html')



@app.route('/', methods=['POST'])
def login():
    username = request.form['username']
    password = request.form['password']

    if authenticate(username, password):
     	# Display success message
        client_ip=request.remote_addr
        client_mac=mac_from_ip(client_ip)
        send_packet(client_mac)
        success_message='Login successful!'
        return success_message
    else:
 	# Display error message
        error_message = 'Login failed. Invalid credentials.'
        return error_message, 401

def authenticate(username, password):
    if username in credentials and credentials[username] == password:
        return True
    return False

if __name__ == '__main__':
    app.run(host='10.0.0.2', port=8888)

