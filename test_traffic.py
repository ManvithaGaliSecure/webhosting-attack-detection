"""
Patent Implementation Reference

Patent Number: 5566676
Patentees: Manvitha Gali and Aditya Mahamkali

Description:
This code demonstrates a reference implementation of Claim 4 from the granted
patent "A Method and a System for Detecting a Malicious Attack on a Network."
It applies DBN-based detection of packet attributes to classify malicious traffic
in a web hosting backend environment.

Copyright (c) 2025 Manvitha Gali and Aditya Mahamkali.
All rights reserved.

Usage of this code is for demonstration, research, and authorized development
purposes only. Any commercial use requires proper licensing of the above patent.
"""

import requests
import random

DBN_URL = "http://127.0.0.1:8000/score"

def simulate_packet():
    size = random.randint(40,1500)
    features = {
        "packet_size": size,
        "packet_length": size,
        "bytes_so_far": random.randint(1000, 50000),
        "mean_packet_length": random.uniform(200, 800)
    }
    return features

if __name__ == "__main__":
    packet = simulate_packet()
    print("Simulated Packet:", packet)
    r = requests.post(DBN_URL, json=packet)
    print("Response:", r.json())
