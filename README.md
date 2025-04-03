# README: **Homing Missile Salvo Deauth** Script

## Overview

This Python script orchestrates a **(proof-of-concept) Wi-Fi Deauthentication Attack** against a chosen network. Once a wireless interface is placed in monitor mode, the script:

1. **Scans** for Access Points (BSSIDs) and collects information (ESSID, encryption type, approximate RSSI, client count).  
2. **Allows the user to select a target** BSSID (the MAC of the Access Point).  
3. **Continuously deauthenticates** clients connected to that target network — **even if**:
   - The target AP switches channels (the script automatically follows it).
   - Clients associate/re-associate with different or randomized MAC addresses (the script rescans to detect newly associated real MACs).  

It also provides a set of **ASCII visuals** (Pyfiglet banner, radar animation, missile launch, and explosion) for a bit of theatrical flair.

> **Disclaimer**: This code is intended for **authorized network testing** and **educational demonstrations** only. Unauthorized use is almost certainly illegal in most jurisdictions.

---

## Key Features

1. **ASCII Art and Animations**  
   - Uses [pyfiglet](https://pypi.org/project/pyfiglet/) to display an attention-grabbing banner.  
   - A background “radar” animation runs concurrently, without blocking the main logic.  
   - Concludes with a “missile launch” and “explosion” ASCII sequence once the deauth process is stopped or the script exits.

2. **Automatic Monitor Mode Setup**  
   - Cleans up leftover monitor interfaces.  
   - Stops common network managers (e.g. NetworkManager) to avoid conflicts.  
   - Uses system commands to put the chosen interface into monitor mode.

3. **Channel Scanning (Countermeasure to Channel Hopping)**  
   - Enumerates all valid channels in 2.4 GHz or 5 GHz (user choice).  
   - Dwells briefly on each channel to detect Wi-Fi networks and potential clients.  
   - **Supervisor** logic constantly checks if the target BSSID has changed its channel, then re-adjusts and resumes deauth.

4. **Rescans for New Clients (Countermeasure to MAC Randomization)**  
   - Modern devices often **randomize their MAC addresses** while unassociated.  
   - Once they associate with a network, they typically use a **non-random, real MAC**.  
   - This script **continuously rescans** for newly associated clients, ensuring it catches devices that may have started out using a random MAC.  
   - Updated clients are then targeted for deauthentication.

5. **Separate Processes for Deauth**  
   - Spawns parallel processes to deauthenticate each client individually, plus a broadcast “general” deauth.  
   - If a process dies, the manager automatically restarts it.

6. **Adaptive Supervisor**  
   - Monitors the existence of the BSSID on its current channel.  
   - If it disappears, the script quickly checks other channels to locate it again.  
   - Keeps re-collecting associated clients on the new channel and restarts the relevant deauth processes.

---

## Requirements

1. **Python 3**  
2. [**Scapy**](https://pypi.org/project/scapy/) – for crafting and sniffing Wi-Fi packets  
3. [**pyfiglet**](https://pypi.org/project/pyfiglet/) – for ASCII art banners

Install with:
```bash
pip install scapy pyfiglet
```

Other utilities that may be needed on Linux:
- **airmon-ng** from the Aircrack-ng suite (for convenience).  

---

## Quick Start

1. **Clone or copy** this script onto a machine with a **monitor-mode capable** Wi-Fi card.  
2. **Install dependencies**:
   ```bash
   pip install scapy pyfiglet
   ```
3. **Run the script** (as **root** or with **sudo**):
   ```bash
   sudo ./deauth_script.py
   ```
4. **Follow the prompts**:
   - The script will list wireless interfaces. Pick your desired interface.  
   - Choose 2.4 GHz or 5 GHz scanning.  
   - The script will attempt to force the chosen interface into **monitor mode**.  
   - It scans available channels to discover BSSIDs, printing some basic details (RSSI, encryption type, and approximate client count).  
   - You then select an AP (by index) to target.  
   - The script shows ASCII art for a “missile launch,” collects client info, and starts the **supervisor** process to continuously deauthenticate.

Press **Ctrl+C** to stop at any point. The script will:
- Terminate all deauth processes.  
- Show an “explosion” ASCII sequence.  
- Attempt to restore normal interface mode by cleaning up leftover monitor interfaces.

---

## Typical Countermeasures Addressed

1. **Channel Hopping**  
   - If the AP frequently switches channels, the supervisor process checks and re-locates it automatically.  
   - It updates the current channel to keep the deauth streams active on the correct frequency.

2. **MAC Address Randomization**  
   - Clients often randomize their MACs for **unassociated** probe requests.  
   - **Once they associate** to the target AP, they typically revert to a consistent MAC.  
   - This script **continuously rescans** for newly associated clients. As soon as a device appears under its real MAC, the script starts deauthenticating it.  

---

## Legal Disclaimer

Performing deauthentication attacks without explicit permission from the network’s owner can be **illegal**. Use this tool only for:
- Testing networks you own
- Networks for which you have **explicit, documented authorization** to audit.

**You are responsible** for any misuse and all legal consequences.

---

## Troubleshooting

- **Monitor Mode Issues**:  
  - Ensure no conflicting processes are holding the interface.  
  - Manually test with `airmon-ng start <interface>` if the script fails to do so automatically.

- **No Networks Found**:  
  - Verify the band selection (2.4 vs. 5 GHz).  
  - Check that your card supports scanning on the chosen band.

- **Permission Errors**:  
  - Must run as root or with sudo for raw packet injection/sniffing.

---

## Contributing

Pull requests, bug reports, and suggestions are welcome (for legitimate **testing** and **educational** purposes). Please follow best practices and ensure the script’s usage remains confined to **authorized scenarios**.

---

## License

Released under the [MIT License](https://opensource.org/licenses/MIT).  
Use responsibly, for legal and ethical security testing only.
