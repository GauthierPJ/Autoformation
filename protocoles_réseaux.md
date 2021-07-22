___
# Appellations

* A (hôte / victime) : 192.168.1.10
* B (passerelle)     : 192.168.1.1 
* H (hacker)         : 192.168.1.17

___
# Couche 2 - Liaison 

* Fonction : cette couche s'occupe de la livraison de **trames** entre appareils d'un même LAN. 
* Protocoles : Ethernet, ATM, PPP, STP

## Ethernet 

Protocole permettant de relier des noeuds (périphériques connectés entre eux) entre eux grâce à des câbles réseaux. <br>

## ATM

## Token ring

## SLIP


___
# Couche 3 - Réseau 

* Fonction : permet le routage, ie la détermination d'un chemin permettant de relier deux machines distantes. 
* Protocoles : ARP, BGP, ICMP, IPv4, IPv6


## ARP 

Objectif : associer une adresse MAC à une adresse IP. Dans un LAN, les appareils communiquent avec des MAC.

1. A : Broadcast : who has 192.168.1.1 ? 
2. B : Répond avec adresse mac, et met à jour son ARP cache avec les informations de A (ip - mac).
3. A : Met à jour son arp cache et peut désormais communiquer avec B.

## IP

Objectif : 

## ICMP

Objectif : 

## BGP

Objectif : protocole de routage (comme RIP, IGRP, OSPF)

___
# Couche 4 (Transport)

* Fonction : gère la communication de bout en bout des processus et corrige les erreurs.
<br> Cette couche utilise des sockets (ip + port) afin de faire communiquer 2 processus distants. Les deux processus sur les deux machines distinctes utilisents 2 ports différents. 
* Protocoles : TCP, UDP, RTP


## TCP (Transmission Control Protocole) 

* Protocole de transport fiable, en mode connecté.
* Les applications transmettent des flux de données sur une connexion réseau : TCP découple les flux d'octets en **segments**.
* Les données arrivent dans le bon ordre grâce aux numéros de séquences et d'acquittement.


Une session TCP se déroule en 3 étapes : 
A est le client, B le serveur.

1. Connexion (3-way handshake) : 
    * A : syn (seq = x)
    * B : syn/ack (seq = y, ack = x+1) 
    * A : ack (seq = x+1, ack = y+1)
2. Transfert des données avec contrôle de sequencing : 
    * A : seq = 43, ack = 79, data_length = 10
    * B : seq = 79, ack = seq + data_length = 43 + 10 = 53 <br>
    => Côté serveur, le seq est le ack du client et le ack et le seq + data_length
3. Terminaison (4-way handshake) indépendante : 
    * A : fin (seq = x)
    * B : ack (ack = x+1)
    * B : fin (seq = y)
    * A : ack (ack = y+1)

*Liste non exhaustive de protocoles fonctionnant sur TCP :  FTP (21), SSH (22), Telnet (23), SMTP (25), HTTP (80), POP3 (110).* 

    

## UDP (User Datagram Protocol)

* Protocole de transport simple, non fiable et sans connexion.
* Le PDU associé à UDP est le **datagramme**.
* Adapté à un usage pour lequel : 
    1. La détection et la correction d'erreurs ne sont pas nécessaires
    2. Transmettre rapidement de petites quantités de données

*Liste non exhaustive de protocoles/process fonctionnant sur UDP : DHCP, DNS, jeux en lignes, streaming, visioconférence.* 

___
# Couche 5 (Session)

* Fonction : 
* Protocoles : TLS, SOCKS

___
# Couche 6 (Présentation)

* Fonction : 
* Protocoles : ASCII, MIME, AFP
___
# Couche 7 (Application)

## DHCP 

Objectif : permet à un hôte arrivant dans un réseau de demander une IP.

**DORA :** 

* A : Discover (broadcast) 
* B : Offer 
* A : Request
* B : Ack
___

# Attaques réseaux

## ARP poisoning (3)

* Objectif       : Détourner les flux de communications entre une machine cible et une passerelle (routeur, box). L'attaquant peut ainsi écouter, modifier et bloquer les paquets réseaux. Attaque MITM.
* Outils         : Scapy (forger des paquets ARP) - Ettercap
* Fonctionnement : L'attaquant envoie en broadcast une requête ARP assimilant son adresse MAC avec l'adresse IP de la victime. 
* Contre-mesure  : Utiliser une table ARP statique, logiciel comme ARPwatch.


## DHCP Spoofing (2)



Attaque MITM. Sous kali linux, Ettercap. Inefficace si trafic chiffré.
Efficace si H répond avant B

1. A : Broadcast : who has 192.168.1.254 ? 
2. H : C'est moi, voici ma MAC.
3. A : Met à jour son arp cache. H est désormais espion.



