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

from fastapi import FastAPI
from pydantic import BaseModel
import numpy as np

app = FastAPI(title="DBN Detection Service")

class Features(BaseModel):
    packet_size: int
    packet_length: int
    bytes_so_far: int
    mean_packet_length: float

def dummy_dbn(features):
    ratio = (features.packet_size + features.packet_length) / (features.mean_packet_length + 1)
    burst = features.bytes_so_far / (features.mean_packet_length + 32)
    score = 1 / (1 + np.exp(-(0.002 * (ratio + burst) - 2.5)))
    return score

@app.post("/score")
def classify(features: Features):
    score = dummy_dbn(features)
    malicious = score >= 0.7
    return {"malicious": malicious, "confidence": float(score)}
