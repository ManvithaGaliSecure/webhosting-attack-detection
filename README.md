# Web Hosting Attack Detection (Patent-Based)

**Patent Number:** 5566676  
**Patentees:** Manvitha Gali & Aditya Mahamkali  

This repository provides a reference implementation of **Claim 4** from the granted patent:  
> *“A Method and a System for Detecting a Malicious Attack on a Network.”*

The project demonstrates how a **web hosting company** can integrate **DBN-based attack detection** at the backend, filtering malicious traffic before it reaches customer websites.

---

## 🔑 Key Features
- **DBN Detection Service (FastAPI):** Analyzes packet attributes (size, length, bytes, mean length).  
- **SDN Controller (Ryu):** Intercepts flows, queries detection service, and enforces decisions.  
- **QoS-aware Routing:** For benign traffic, forwards via shortest + QoS-optimized path.  
- **Traffic Simulator:** Generates benign/malicious packets to test the system.  

---

## ⚙️ How to Run Locally
```bash
# Install dependencies
pip install -r requirements.txt

# Start detection service
uvicorn detection_service.app:app --host 0.0.0.0 --port 8000

# Simulate traffic
python examples/test_traffic.py

