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

import networkx as nx

def qos_penalty(edge):
    qos = edge.get('qos', {})
    return (
        qos.get('pair_flow_entries', 0.1) +
        qos.get('flow_entry_rate', 0.01) +
        (0.1 / (1 + qos.get('stdev_bytes', 1.0))) +
        (0.1 / (1 + qos.get('stdev_packets', 1.0))) +
        qos.get('source_ip_rate', 0.01)
    )

def shortest_qos_path(G, src, dst):
    for u, v, data in G.edges(data=True):
        data['weight'] = data.get('distance', 1.0) + qos_penalty(data)
    return nx.shortest_path(G, src, dst, weight='weight')
