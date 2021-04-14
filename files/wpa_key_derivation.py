#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
Derive WPA keys from Passphrase and 4-way handshake info

Calcule un MIC d'authentification (le MIC pour la transmission de données
utilise l'algorithme Michael. Dans ce cas-ci, l'authentification, on utilise
sha-1 pour WPA2 ou MD5 pour WPA)
"""

__author__ = "Abraham Rubinstein et Yann Lederrey"
__modified__ = "Robin Müller et Stéphane Teixeira Carvalho"
__copyright__ = "Copyright 2017, HEIG-VD"
__license__ = "GPL"
__version__ = "1.0"
__email__ = "abraham.rubinstein@heig-vd.ch"
__status__ = "Prototype"

from scapy.all import *
from binascii import a2b_hex, b2a_hex
from scapy.contrib.wpa_eapol import WPA_key
from scapy.layers.dot11 import *

from pbkdf2 import *
import hmac, hashlib


def customPRF512(key, A, B):
    """
    This function calculates the key expansion from the 256 bit PMK to the 512 bit PTK
    """
    blen = 64
    i = 0
    R = b''
    while i <= ((blen * 8 + 159) / 160):
        hmacsha1 = hmac.new(key, A + str.encode(chr(0x00)) + B + str.encode(chr(i)), hashlib.sha1)
        i += 1
        R = R + hmacsha1.digest()
    return R[:blen]


def getAssociationRequestInfo(packets):
    """
    Will get all the values useful from an association request packet
    :param packets: the list of packets
    :return: the ssid of the AP, the MAC of the AP and the Client
    """
    # Search for an association request in the list of packets
    assocRequests = list(filter(lambda pkt: pkt.haslayer(Dot11AssoReq), packets))
    # Exception if we do not find any association request
    if len(assocRequests) == 0:
        raise Exception("Cannot find association request")

    # Retrieve info from the first association request found
    pkt = assocRequests[0]
    # info will give the ssid of the AP
    ssid = pkt.info.decode('ascii')
    # addr1 is where the MAC of the AP is stored in the first association request in our case
    APmac = a2b_hex(pkt.addr1.replace(':', ''))
    # addr2 is where the MAC of the client is stored in the first association request in our case
    Clientmac = a2b_hex(pkt.addr2.replace(':', ''))
    return ssid, APmac, Clientmac


def getHandshakeInfo(packets):
    """
    Will get all the values useful from the 4 way handshake packets.
    Handshake packets must be in order.
    :param packets: the list of packets
    :return: the authenticator nonce, the supplicant nonce, the mic of the fourth message and the data of the fourth message
    """
    # Search for all the packets that have the layer WPA_key (This will return the 4 way handshake packets)
    pkts = list(filter(lambda pkt: pkt.haslayer(WPA_key), packets))
    if len(pkts) != 4:
        raise Exception("Invalid handshake")
    # Get the WPA_layer of the packets found contains the value of the handshake
    handshakePkts = list(map(lambda pkt: pkt.getlayer(WPA_key), pkts))

    # Authenticator and Supplicant Nonces
    ANonce = handshakePkts[0].nonce  # ANonce in first message of the handshake
    SNonce = handshakePkts[1].nonce  # SNonce in second message of the handshake

    # This is the MIC contained in the 4th frame of the 4-way handshake
    # When attacking WPA, we would compare it to our own MIC calculated using passphrases from a dictionary
    mic = handshakePkts[3].wpa_key_mic  # mic in fourth message of the handshake

    handshakePkts[3].wpa_key_mic = 0  # Zero the mic key to remove the value from the data
    # Get the data of the last packet without the mic
    data = bytes(handshakePkts[3].underlayer)

    return ANonce, SNonce, mic, data

def main():
    # Read capture file -- it contains beacon, authentication, association, handshake and data
    wpa = rdpcap("wpa_handshake.cap")

    # Important parameters for key derivation - most of them can be obtained from the pcap file
    passPhrase = "actuelle"
    A = "Pairwise key expansion"  # this string is used in the pseudo-random function

    ssid, APmac, Clientmac = getAssociationRequestInfo(wpa)
    ANonce, SNonce, mic_to_test, data = getHandshakeInfo(wpa)

    B = min(APmac, Clientmac) + max(APmac, Clientmac) + min(ANonce, SNonce) + max(ANonce,
                                                                                  SNonce)  # used in pseudo-random function
    print("\n\nValues used to derivate keys")
    print("============================")
    print("Passphrase: ", passPhrase, "\n")
    print("SSID: ", ssid, "\n")
    print("AP Mac: ", b2a_hex(APmac), "\n")
    print("CLient Mac: ", b2a_hex(Clientmac), "\n")
    print("AP Nonce: ", b2a_hex(ANonce), "\n")
    print("Client Nonce: ", b2a_hex(SNonce), "\n")

    # calculate 4096 rounds to obtain the 256 bit (32 oct) PMK
    passPhrase = str.encode(passPhrase)
    ssid = str.encode(ssid)
    pmk = pbkdf2(hashlib.sha1, passPhrase, ssid, 4096, 32)

    # expand pmk to obtain PTK
    ptk = customPRF512(pmk, str.encode(A), B)

    # calculate MIC over EAPOL payload (Michael)- The ptk is, in fact, KCK|KEK|TK|MICK
    mic = hmac.new(ptk[0:16], data, hashlib.sha1)

    print("\nResults of the key expansion")
    print("=============================")
    print("PMK:\t\t", pmk.hex(), "\n")
    print("PTK:\t\t", ptk.hex(), "\n")
    print("KCK:\t\t", ptk[0:16].hex(), "\n")
    print("KEK:\t\t", ptk[16:32].hex(), "\n")
    print("TK: \t\t", ptk[32:48].hex(), "\n")
    print("MICK:\t\t", ptk[48:64].hex(), "\n")
    print("MIC:\t\t", mic.hexdigest(), "\n")

if __name__ == "__main__":
    main()
