# Web Hosting Attack Detection (Patent-Based)

This project demonstrates how a web hosting company can implement **Claim 4** of Patent Number 5566676
by Manvitha Gali and Aditya Mahamkali.

## Features
- DBN Detection Service (FastAPI)
- Ryu SDN Controller Integration
- QoS-aware Shortest Path Routing
- Example traffic simulator

## Run Example
```bash
pip install -r requirements.txt
uvicorn detection_service.app:app --reload
python examples/test_traffic.py
```

## License
© 2025 Manvitha Gali and Aditya Mahamkali. All rights reserved.
Commercial usage requires licensing of Patent 5566676.
