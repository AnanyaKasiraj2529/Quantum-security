# 🔐 Quantum-Safe Hybrid Key Distribution for IoT
BB84 Quantum Key Distribution + Lattice-Based Post-Quantum Authentication
![Python](https://img.shields.io/badge/Python-3.10-blue.svg)
![Research](https://img.shields.io/badge/Research-Quantum--Safe-green)
![Post-Quantum](https://img.shields.io/badge/Cryptography-Post--Quantum-orange)
![QKD](https://img.shields.io/badge/Protocol-BB84-purple)
![License](https://img.shields.io/badge/License-MIT-blue.svg)
![Status](https://img.shields.io/badge/Status-Research%20Simulation-success)

## Original Implementation

All algorithms and simulations in this repository were independently
implemented as part of my undergraduate research project on
quantum-safe authentication for IoT systems.

No tutorial or external implementation was reused.

Official IEEE publication link: https://scholar.google.com/citations?view_op=view_citation&hl=en&user=f-wHAfsAAAAJ&citation_for_view=f-wHAfsAAAAJ:u5HHmVD_uO8C

📌 Project Overview
<img width="608" height="368" alt="image" src="https://github.com/user-attachments/assets/c91d85c6-9145-4f2a-af3e-a64cb347a439" />

This repository presents a hybrid quantum-safe communication framework that integrates:
- BB84 Quantum Key Distribution (QKD)
- Lattice-Based Post-Quantum Cryptography (PQC)
- Hybrid QKD + PQC Authentication Model
- Quantum Bit Error Rate (QBER) Analysis
- Eavesdropper (Eve) Attack Simulation
The goal is to design and simulate a quantum-resilient key exchange protocol suitable for resource-constrained IoT environments, addressing scalability, side-channel risks, and future quantum threats.
This implementation supports the research work presented in:
Quantum-Safe Protocols Design for IoT Communications: Critical Observation and Analysis (CISCON 2025)

## My Contributions

- Implemented BB84 QKD protocol simulation from scratch
- Designed hybrid key distribution workflow
- Integrated lattice-based authentication model
- Developed comparative performance evaluation framework

🧠 Motivation
With the rise of quantum computing:
- Classical cryptographic schemes (RSA, ECC) are vulnerable to Shor’s Algorithm
- IoT systems operate under low power and limited computation
- Pure QKD systems suffer from scalability and noise sensitivity
- Lattice-based cryptography faces side-channel vulnerabilities
This project explores a hybrid security architecture combining the strengths of both paradigms.

## Methodology

1. Simulated quantum key exchange using BB84 principles
2. Generated classical secure channel
3. Integrated PQC authentication layer
4. Evaluated latency and security trade-offs

##🔬 Implementation architecture design

1️⃣ BB84 Quantum Key Distribution
Simulates:
Random bit generation
Random basis selection (Z / X)
Measurement process
Key sifting
Secure shared key formation

2️⃣ Lattice-Based Encryption (LWE-Inspired)
Implements:
Public matrix generation
Error sampling
Encryption:
c = A·m + e mod q
Decryption via approximate inversion

3️⃣ Hybrid QKD + PQC Model
Workflow:
Generate QKD shared key
Apply lattice-based authentication
Perform layered encryption
Evaluate correctness

4️⃣ QBER & Attack Analysis
Simulates:
Intercept-resend Eve attack
Error introduction in quantum channel
QBER comparison (clean vs attacked channel)
Expected Results:

Scenario	QBER
No Attack	≈ 0
With Attack	20–30%



##📊 Key Experimental Results

✔ ~50% key retention in BB84
✔ Successful lattice encryption & decryption
✔ Detectable QBER increase under attack
✔ Demonstration of hybrid quantum-safe layering

🛡 Security Insights
This hybrid approach:
Provides quantum-safe key exchange
Adds post-quantum authentication
Improves resilience against:
Quantum computing attacks
Side-channel threats
Eavesdropping attempts
Supports scalability research for IoT systems

🚀 How to Run:
1️⃣ Clone Repository
git clone https://github.com/yourusername/Quantum-Safe-BB84-Lattice-Hybrid.git
cd Quantum-Safe-BB84-Lattice-Hybrid
2️⃣ Install Dependencies
pip install -r requirements.txt
3️⃣ Run Notebooks
jupyter notebook

🔮 Future Research Directions
Integration with Cirq or Qiskit quantum circuits
RLWE-based cryptographic expansion
AI-based side-channel detection
Error correction (Steane Code)
IoT computational benchmarking
Hybrid protocol latency optimization

📚 Research Contribution
This repository bridges:
Quantum cryptography
Post-quantum cryptography
Hybrid secure protocol design
IoT security architecture

It serves as:
Research support material
Simulation framework
Educational reference
Foundation for quantum-safe protocol experimentation

📜 Citation
If you use this work, please cite:

Kasiraj et al.,
Quantum-Safe Protocols Design for IoT Communications:
Critical Observation and Analysis,
CISCON 2025.

👩‍💻 Author
Ananya Kasiraj
Cybersecurity Researcher
Quantum-Safe Cryptography | IoT Security | Post-Quantum Systems


