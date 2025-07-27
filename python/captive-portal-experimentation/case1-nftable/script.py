# 
from scapy.all import DHCP, IP, BOOTP, UDP, sendp, send,Ether,sniff,wrpcap
from ipaddress import *
from datetime import timedelta, datetime
'''
RESSOURCES

- The IETF 1997 paper on DHCP (rfc2131) : https://www.ietf.org/rfc/rfc2131.txt
- Microsoft Learn : DHCP concepts : https://learn.microsoft.com/fr-fr/windows-server/troubleshoot/dynamic-host-configuration-protocol-basics 
- A scapy DHCP Listener : https://jcutrer.com/python/scapy-dhcp-listener
- 'A customized DHCP Server in python using scapy : https://projects2009developer.files.wordpress.com/2009/03/scapy.pdf'
'''
# Addresses pools : 
trusted_pool = ["10.0.2."+str(i) for i in range(2,255)]
untrusted_pool = ["10.0.1."+str(i) for i in range(2,255)]
# Used IPs : 
assigned_trusted_ips = []
assigned_untrusted_ips = []
# Lease time (sec)
lease_trusted=180 
renew_time_trusted=60
rebinding_time_trusted=160
lease_untrusted=20
renew_untrusted=10
rebinding_untrusted=15
# Interfaces to listen
interfaces=["eth1","eth2","eth3","eth4"]
srcmac="02:42:d1:22:22:22"
validated_macs=[]
waiting_list_untrusted=[]
waiting_list_trusted=[]
remining_times={}
'''
option_value field pkt[DHCP].option[0][1]
    1: DHCP Discover
    2: DHCP Offer
    3: DHCP Request
    4: DHCP Decline
    5: DHCP Acknowledgement (ACK)
    6: DHCP Negative Acknowledgement (NAK)
    7: DHCP Release
    8: DHCP Information Request
    9: DHCP Lease Query
    10: DHCP Lease Unassigned
    11: DHCP Lease Unknown
    12: DHCP Lease Active
siaddr = server ip address 
yiaddr = "your IP address" (proposed to the client)
chaddr = client hardware address (client's MACprint("DHCP OFFER sent with IP: ",choosen_ip," proposal"))
pkt.sniffed_on => gives the packet intput interface
'''
def set_remining_time(ip,lease):
    remining_times[str(ip)] = datetime.now() + timedelta(seconds=lease)

def is_finished(ip):
    return datetime.now()>remining_times[str(ip)]
    
def find_requested_address(pkt):
    # In the pkt[DHCP].options field, other args than messag_type can move so have to loop to find the requested IP of REQUEST packets
    for option in pkt[DHCP].options:
        #print(option)
        if option[0] == "requested_addr":
           return option[1]
    return pkt[IP].src
def translate_client(address):
    # Problem when asking for client hardware address in BOOTP : the format isnt 'string MAC'
    # Format in bytes => hex (with too much 00:00 at the end) 
    # Take only the first (MAC addr) part
	mac_ = ":".join(format(byte, '02x') for byte in address)
	chaddr = mac_[:17]
	return str(chaddr)	
def contains(list, element):
    # Very usefull for a lot of operations
	for ele in list:
		if ele == element:
			return True
	return False

def select_given_ip(bool):
    if bool: #True = trusted : choose an ip in trusted_pool that is not already in assigned_trusted_ips
        i=0
        while(contains(assigned_trusted_ips, trusted_pool[i])): # While already assigned
             if(i<254): # Cap
                i+=1
             else:
                print("WARNING NO MORE ADDRESSES AVAILABLE IN TRUSTED POOL")
                break        
        assigned_trusted_ips.append(trusted_pool[i])
        print(trusted_pool[i],"REMOVED FROM AVAILABLE TRUSTED POOL")
        return trusted_pool[i]
        
    else: # False = untrusted : choose an ip in untrusted_pool that is not already in assigned_untrusted_pool
        i=0
        while(contains(assigned_untrusted_ips, untrusted_pool[i])):
            if(i<254):
                i+=1
            else:
                print("WARNING NO MORE ADDRESSES AVAILABLE IN UNTRUSTED POOL")
                break        
        assigned_untrusted_ips.append(untrusted_pool[i])
        print(untrusted_pool[i],"REMOVED FROM AVAILABLE UNTRUSTED POOL")
        return untrusted_pool[i]   

def send_offer(given_ip,client_mac,client_mac_bytes,input_interface,cxid,lease): # OFFER
    # Packet crafting
    ans = Ether(src=srcmac,dst=client_mac)/ \
    IP(src="10.0.1.1",dst="255.255.255.255")/ \
    UDP(sport=67,dport=68)/ \
    BOOTP(op=2,yiaddr=str(given_ip),siaddr="10.0.1.1",chaddr=client_mac_bytes,xid=cxid)/ \
    DHCP(options=[('message-type','offer'),('subnet_mask','255.255.255.0'),('lease_time',lease),("server_id", "10.0.1.1"), ("renewal_time",lease//2),("broadcast_address", "10.0.1.255"),("router", "10.0.1.1"),('name_server','10.0.1.1'),('renewal_time',3*lease//4),('rebinding_time',15),"end"])
    # Packet sending
    sendp(ans,iface=str(input_interface),verbose=False)
    # Log
    print("ROUTER =======OFFER======>",client_mac,input_interface,cxid,"PROPOSED",given_ip) 
def send_ack(client_mac,mac_client_bytes,client_ip,lease,input_interface,cxid):
    # Packet crafting    
    ans = Ether(src=srcmac,dst=client_mac) /\
    IP(src='10.0.1.1',dst=client_ip)/\
    UDP(sport=67,dport=68)/\
    BOOTP(op=2,yiaddr=client_ip,xid=cxid,chaddr=mac_client_bytes,siaddr='10.0.1.1')/\
    DHCP(options=[('message-type','ack'),('lease_time',lease),('subnet_mask','255.255.255.0'),("server_id", "10.0.1.1"),("broadcast_address", "10.0.1.255"),("router", "10.0.1.1"),('name_server','10.0.1.1'),('renewal_time',lease//2),('rebinding_time',3*lease//4),"end"])
    # Packet sending    
    sendp(ans, iface=str(input_interface),verbose=False)
    # Set lease time into the script
    set_remining_time(client_ip,lease)
    # Log    
    print("ROUTER =======ACK======>",client_mac,client_ip,cxid)


def send_nak(input_interface,client_mac,client_ip,cxid):
    # Packet crafting    
    nak = Ether(src=srcmac,dst=client_mac) / \
        IP(src="10.0.1.1", dst=client_ip) / \
	    UDP(sport=67, dport=68) / \
        BOOTP(op=2,yiaddr='0.0.0.0',chaddr=client_mac,siaddr='10.0.1.1',xid=cxid) / \
        DHCP(options=[('message-type', 'nak'),("server_id","10.0.1.1"), ("end")])
     # Packet sending   
    sendp(nak,iface=str(input_interface),verbose=False)
    print("ROUTER >>>>>>>NAK>>>>>>>",client_mac,client_ip,cxid)

def send_forcerenew(input_interface,client_mac,client_ip):
    # Packet crafting
    forcerenew = Ether(dst=client_mac,src=srcmac) / \
    IP(src="10.0.1.1",dst=client_ip) / \
    UDP(sport=67,dport=68) / \
    BOOTP(chaddr=client_mac) / \
    DHCP(options=[('message-type','force_renew'),'end'])
    # Packet sending
    sendp(forcerenew,iface=str(input_interface),verbose=False)
    # Log
    print("ROUTER >>>>>>>FORCERENEW>>>>>>>",client_ip,client_mac)
    # Remark : The forcerenew message SHOULD put the client in INIT status. THUS the client will ask to renew its lease according to the standard DHCP procedure. So the client still needs to receive a NAK in order to get another IP, but maybe the FORCERENEW packet will speed up the procedure.
    

def dhcp_handler(pkt):
    # Check for ghost addresses
    for ip in assigned_trusted_ips:
        if is_finished(ip):
            remining_times.pop[str(ip)]
    for ip in assigned_untrusted_ips:
       if is_finished(ip):
           remining_times.pop[str(ip)]   

    input_client_ip=pkt[IP].src
    input_interface=pkt.sniffed_on
    
    # RECEIVES PYSERVER SUCCESSFUL AUTHENTICATION 
    # Then client mac will be the dst mac (instead of the chaddr)
    # If the client mac address is validated, we send a FORCERENEWAL packet to the client. 
    if pkt[IP].src=="1.2.3.4" and input_interface=="eth4":
        client_mac=pkt[Ether].dst
        if contains(validated_macs,client_mac):
            print("VALIDATED MACs LIST ALREADY CONTAINS",client_mac)
            print("VALIDATED LIST IS NOW",validated_macs)
        else:
            validated_macs.append(client_mac)
            print("ROUTER <======VALIDATION======= PYSERVER")
            print("MAC: ",client_mac," ADDED TO VALIDATED LIST... WAITING FOR DHCP RENEWAL TO GIVE AUTH ACCESS")   
            print("VALIDATED LIST IS NOW:",validated_macs)
            send_forcerenew(input_interface,client_mac,input_client_ip)
            
            

    # RECEIVES A DHCP RELEASE FROM CLIENT 
    elif  DHCP in pkt and pkt[DHCP].options[0][1] == 7:
        client_ip=pkt[IP].src
        client_mac=pkt[Ether].dst
        print("ROUTER <======RELEASE=======",client_mac,client_ip)
        # Removal from waiting_list (First renewal request of the client)
        if contains(waiting_list_untrusted,client_mac):
            waiting_list_untrusted.remove(client_mac)
        if contains(waiting_list_trusted):
            waiting_list_trusted.remove(client_ip)
        if contains(assigned_trusted_ips,client_ip):
            assigned_trusted_ips.remove(client_ip)
            validated_macs.remove(client_mac)
            print(client_ip,"REMOVED FROM TRUSTED_IPS",client_mac,"REMOVED FROM VALIDATED_MACS")
            print("ASSIGNED TRUSTED_IPS ARE NOW",assigned_trusted_ips)
            print("VALIDATED_MACS ARE NOW",validated_macs)
        else:
            assigned_untrusted_ips.remove(client_ip)
            print(client_ip,"REMOVED FROM UNTRUSTED_IPS")
            print("ASSIGNED UNTRUSTED_IPS ARE NOW",assigned_untrusted_ips)
    
    # RECEIVES OTHER DHCP PACKETS (DISCOVER OR REQUEST)
    else:
        # Variables that wont move in the case of full DHCP packet
        cxid=pkt[BOOTP].xid
        client_mac_bytes=pkt[BOOTP].chaddr
        client_mac = translate_client(pkt[BOOTP].chaddr)
        #print("TEST DIFF CHADDR & ETHER MAC:",client_mac,pkt[Ether].src)

        # RECEIVES DHCP DISCOVER (THEN SEND OFFER)
        if DHCP in pkt and pkt[DHCP].options[0][1] == 1: 
            # If mac in validated_macs (means offer trusted ip)
            # else mac not in validated_macs (means offer untrusted_ip)
            # && contains(waiting_list) to ensure that the client wont receive and take more than one IP
            if contains(validated_macs, client_mac) and contains(waiting_list_trusted, client_mac) and contains(assigned_trusted_ips, find_requested_address(pkt)):
                print("ROUTER <======DISCOVER FOR 'RENEW' TRUSTED =======",client_mac,input_interface,cxid,input_client_ip)
                send_offer(find_requested_address(pkt),client_mac,client_mac_bytes,pkt.sniffed_on,cxid,lease_trusted)
            if contains(validated_macs, client_mac) and not contains(waiting_list_trusted,client_mac):
                choosen_ip=select_given_ip(True)
                waiting_list_trusted.append(client_mac)
                waiting_list_untrusted.remove(client_mac)
                print("ROUTER <======DISCOVER TRUSTED=======",client_mac,input_interface,cxid,input_client_ip)
                send_offer(choosen_ip,client_mac,client_mac_bytes,pkt.sniffed_on,cxid,lease_trusted)
                
            elif not contains(waiting_list_untrusted,client_mac) and not contains(waiting_list_trusted,client_mac): 
                choosen_ip=select_given_ip(False)
                waiting_list_untrusted.append(client_mac)
                print("ROUTER <======DISCOVER=======",client_mac,input_interface,cxid,input_client_ip)
                send_offer(choosen_ip,client_mac,client_mac_bytes,pkt.sniffed_on,cxid,lease_untrusted)
                
        # RECEIVES DHCP REQUEST (THEN SEND ACK/NAK)
        elif DHCP in pkt and pkt[DHCP].options[0][1] == 3: #DHCP Request
            requested_addr=find_requested_address(pkt)

            if pkt[BOOTP].ciaddr == '0.0.0.0': # if new client
                print("ROUTER <<<<<<<REQUEST NEW ADDRESS <<<<<<<",client_mac,input_interface,cxid,"ASKS",requested_addr)
                send_ack(client_mac,client_mac_bytes,requested_addr,30,pkt.sniffed_on,cxid)
            else: # If renewal
                if contains(assigned_trusted_ips,requested_addr) or contains(assigned_trusted_ips,pkt[IP].src): # Trusted Client renewal
                    print("ROUTER <<<<<<<REQUEST RENEWAL TRUSTED IP<<<<<<<",client_mac,input_interface,cxid,"ASKS",requested_addr)
                    send_ack(client_mac,client_mac_bytes,requested_addr,20,pkt.sniffed_on,cxid)
                else: # Untrusted client renewal
                    if contains(validated_macs,client_mac): # if untrusted client that successfully AUTH
                        print("ROUTER <<<<<<<REQUEST RENEWAL AFTER SUCCESS AUTH.<<<<<<<",pkt[IP].src,client_mac,input_interface,cxid,"ASKS",requested_addr)
                        # Removal from waiting_list (First renewal request of the client)
                        #if contains(waiting_list,client_mac):
                        #    waiting_list.remove(client_mac)
                        send_nak(pkt.sniffed_on,client_mac,pkt[BOOTP].ciaddr,cxid)
                    else: # Untrusted renweal of client that has not successfully auth yet
                        print("ROUTER <<<<<<<REQUEST RENEWAL FOR UNTRUSTED<<<<<<<",client_mac,input_interface,cxid,"ASKS",requested_addr)
                        send_ack(client_mac,client_mac_bytes,requested_addr,20,pkt.sniffed_on,cxid)

    '''else: # Other than DHCP 
        print("Packet received from IP: ",pkt[IP].src,\
        " and MAC: ",pkt[Ether].src, \
        " on interface: ",pkt.sniffed_on," but hasn't been detected as a DHCP packet")'''

def main():
    print("DHCP Handler now listen on 67 ")
    sniff(iface=interfaces,filter="udp port 67",prn=dhcp_handler,store=0)


main()




