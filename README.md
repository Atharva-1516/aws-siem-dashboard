
---

## ⚙️ Features

- Real-time AWS event monitoring
- Alert severity classification (High / Medium / Low)
- Detection of suspicious activities (e.g., security group changes, root actions)
- Interactive dashboard with:
  - KPI metrics (Total Alerts, Severity breakdown)
  - Event timeline
  - Source IP tracking
  - Threat distribution visualization
- Data processing and normalization using Python

---

## 🧠 What This Project Demonstrates

- SIEM pipeline design and implementation
- Cloud security monitoring fundamentals
- Detection engineering concepts
- AWS service integration
- Data visualization for security operations

---

## 🛠️ Tech Stack

- **AWS CloudTrail** – Event logging  
- **AWS Lambda** – Alert processing & detection logic  
- **AWS SNS** – Notification system  
- **AWS DynamoDB** – Alert storage  
- **Python (Boto3, Pandas)** – Data processing  
- **Streamlit** – Dashboard UI  

---

## 📊 Dashboard Preview

![Dashboard](screenshots/dashboard.png)

---

## 📦 Installation

### 1. Clone the repository
```bash
git clone https://github.com/Atharva-1516/aws-siem-dashboard.git
cd aws-siem-dashboard
