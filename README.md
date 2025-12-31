# THACH SENSOR - NETWORK INTELLIGENCE UNIT

> Advanced Passive ARP Reconnaissance & Device Fingerprinting System
> Version: 18.5 Ultimate Edition

![Python](https://img.shields.io/badge/Python-3.10%2B-00599C?style=flat-square&logo=python&logoColor=white)
![Network](https://img.shields.io/badge/Network-Scapy-green?style=flat-square)
![License](https://img.shields.io/badge/License-MIT-grey?style=flat-square)

## Project Overview

Thach Sensor V18.5 is a specialized Local Area Network (LAN) monitoring system developed in Python. It operates on a Zero Trust architecture, utilizing passive ARP (Address Resolution Protocol) sniffing to detect, identify, and log every device entering the network in real-time.

Unlike standard network scanners that require active probing (which can be detected by firewalls), Thach Sensor listens passively to broadcast traffic, making it stealthy and efficient. It integrates a Telegram Bot API to deliver instant security alerts to the administrator's mobile device.

---

## System Architecture & Logic

This tool is a multi-threaded application designed for performance and reliability. Below is the breakdown of the core logic implemented in the source code:

### 1. Concurrent Execution (Multi-threading)
The system utilizes `ThreadPoolExecutor` with 50 worker threads. Standard sequential scanning is often slow because waiting for a port scan on one device blocks the detection of others. By offloading analysis tasks to background workers, Thach Sensor ensures the main sniffing loop never freezes (Non-blocking I/O).

### 2. Smart Persistence Engine
Most scanners annoy users with alerts for known devices (phones, laptops) every time the script restarts. Thach Sensor solves this by maintaining a persistent state layer:
* **Session State (RAM):** Tracks what is online in the current session.
* **History State (Disk):** Tracks devices that have been detected in the past via a JSON database.
* **Logic:** The system compares new connections against the history database. Alerts are only sent if the MAC address is completely new.

### 3. Advanced Device Fingerprinting
The system goes beyond simple OUI (Vendor) lookups. It attempts to connect to specific service ports to classify the device type accurately:
* **Port 554:** Identifies Surveillance Cameras (RTSP).
* **Port 62078/5353:** Identifies Apple/iOS Devices.
* **Port 3389:** Identifies Windows Workstations (RDP).
* **Port 80/443:** Identifies Web Servers or Gateways.

---

## Installation<>

### Prerequisites
* **OS:** Windows 10/11 (Recommended) or Linux/macOS.
* **Python:** Version 3.8 or higher.
* **Driver (Windows Only):** You must install Npcap to allow Python to capture packets. Note: Check "Install Npcap in WinPcap API-compatible Mode" during installation.

### Step 1: Clone the Repository
```bash
git clone [https://github.com/vanthach2527/Thach-Sensor-V18.git](https://github.com/vanthach2527/Thach-Sensor-V18.git)
cd Thach-Sensor-V18