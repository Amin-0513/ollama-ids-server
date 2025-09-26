# ollama-IDS-Server

![ollama-ids-server](/neo4j.PNG)

This backend implements a comprehensive LLM-assisted Intrusion Detection System (IDS) designed to bridge machine learning, knowledge graphs, and natural language reporting for advanced cybersecurity analysis. The system begins by training on the NSL-KDD dataset to detect and classify malicious network activities into four primary categories: Remote-to-Local (R2L), User-to-Root (U2L), Probe, and Distributed Denial of Service (DDoS). Once attacks are identified, the pipeline maps each incident to potentially violated Common Vulnerabilities and Exposures (CVEs), creating a structured vulnerability dataset. These mappings are further enriched by constructing a Neo4j knowledge graph that captures relationships between attacks, services, and vulnerabilities. To improve detection accuracy, classification is performed using XGBoost, and reasoning over the knowledge graph is leveraged to infer the most likely CVEs linked to an attack. Finally, for reporting and analyst support, Ollama’s LLaMA-based LLM is integrated to automatically generate human-readable incident reports, translating raw technical classifications into clear narratives that highlight possible CVEs, their impact, and remediation insights. This workflow provides a scalable and intelligent backend framework for intrusion detection, vulnerability mapping, and automated cybersecurity reporting.

## Prerequisites: Install WinPcap or Npcap

Before running the IDS backend or capturing network traffic, you need to install a packet capture library. This project supports **Npcap** (recommended) or **WinPcap**.

### 1. Npcap (Recommended)
- Visit the official Npcap website: [https://npcap.com/](https://npcap.com/)  
- Download the latest version for Windows.  
- Run the installer and follow the prompts.  
  - Make sure to enable **“Install Npcap in WinPcap API-compatible mode”** if you plan to use legacy software.  
- After installation, verify Npcap is working by running your application or using a tool like Wireshark.

### 2. WinPcap (Legacy)
- Visit the official WinPcap download page: [https://www.winpcap.org/install/](https://www.winpcap.org/install/)  
- Download and install the appropriate version for your system.  
- **Note:** WinPcap is no longer actively maintained; Npcap is recommended for modern Windows systems.

> 💡 **Tip:** Npcap is compatible with most modern Windows 10/11 setups, provides better performance, and is actively updated.

### 3. Set Up Neo4j Knowledge Graph

1. Visit the official Neo4j website: [https://neo4j.com/](https://neo4j.com/)  
2. Create a free account or use an existing account.  
3. Download your database credentials (username, password, and connection URI).  
4. Update the corresponding configuration in the project code with your Neo4j credentials.





## 🚀 Getting Started

Follow these steps to set up the project locally.

### Prerequisites
- python (>= 3.12)
- and install mongoDB compass local version
pip

### Installation
```bash
# Clone the repository
git clone https://github.com/Amin-0513/ollama-ids-server.git

# Navigate to project directory
cd ollama-ids-server

# create python environment
python -m venv IDS

# activate python environment
IDS\Scripts\activate

# Install dependencies
pip install -r requirments.txt

## Start project
python threads.py

#or run parallel these commands

#1
uvicorn app:app --host 0.0.0.0 --port 8000 --reload
#2
python ml_ids.py
#3
python tranditionalapi.py
#4
python live_traffic.py
