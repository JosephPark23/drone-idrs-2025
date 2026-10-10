# *An Intrusion Detection/Response System for DJI Drones*

[![DOI](https://img.shields.io/badge/DOI-10.2514%2F6.2026--114726-blue)](https://doi.org/10.2514/6.2026-114726) [![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE) ![Python](https://img.shields.io/badge/python-3.10%2B-blue)

**George Mason Cyber Innovation Lab Research - Summer/Winter 2025**

### <u>Table of Contents</u>

***About the Project***

- [Introduction](#introduction)

- [Publication & Recognition](#publications-recognition)

- [Background](#background)

- [Repository Structure](#repository-structure)

***System Design & Research Overview***

- [Research & System Design](#ureseach-system-designu)

- [IDRS Flow Diagram](#idrs-control-flow-diagram)

***Installation & Usage***

- [Requirements](#requirements)

- [Installation](#installation)

- [Usage](#usage)

- [Configuration Reference](#configuration-reference)

***Miscellaneous***

- [Responsible Use Warning](#responsible-use)

- [Citation](#citation)

- [Acknowledgements](#acknowledgments)

- [MIT License](#license)

---

### <u>Introduction</u>

**To provide some context, my name is Joseph Park, and I am a student researcher interested in cybersecurity** (specific interests include applied cryptography, AI privacy, cyber-physical systems, and offensive security). Some time ago I did vulnerability testing with a DJI Neo, and I thought the results were interesting enough to post online. As a bonus, I wrote some code for a system that would defend the drone from the very same attacks I created.  This system is also included within the repo. 

**For my reflections and personal thoughts on this project, please see the *[Limitations and Reflections](https://github.com/JosephPark23/drone-idrs-2025/blob/main/README.md#limitations-reflections-and-motivations)* section.**

Thank you for reading!

---

### Publications & Recognition

This repository is the companion code for the following conference paper and fair submissions:

**Conference Paper:**

> **Real-Time Detection and Active Mitigation of Command-and-Control Link Exploits in Consumer UAVs**
> 
> Joseph Park, Matthew E. Jablonski. AIAA Regional Student Conferences, 2026.
> 
> https://doi.org/10.2514/6.2026-114726
> 
> **Awards:** 1st Place, High School Category, 2026 AIAA Region I Student Conference

**Fair Submissions**

> *2026 Regeneron Westchester Science & Engineering Fair*
> 
> **Awards:** 4th Place, Computer Science; New York Invents Award

> *2026 Tri-County Science & Technology Fair*
> 
> **Awards:** 3rd Place, Engineering & Technology

> *2025 Somers Science Fair*
> 
> **Awards:** 2nd Place, Computer Science

---

### Background

**TL;DR**: *For my research, I created an IDRS that defended DJI drones from Wi-Fi attacks. This project progressed through two phases: first, an initial penetration testing and vulnerability assessment phase was conducted to understand the flaws of the study drone's security protocols. The second phase constructed a system that covered for the security flaws and prevented exploits.*

**Fun Version**

**I had a wonderful opportunity in the summer of 2025 (and into the spring) to work on some drone hacking at George Mason's cybersecurity lab**, and many, many thanks are due to **Dr. Matthew Jablonski** and **Jad Zarzour**, plus **Dr. Duminda Wijesekera** for accepting me into the lab (I seriously can't thank them enough)!

---

### Repository structure


```
drone-idrs-2025/
├── README.md
├── LICENSE
├── CITATION.cff
├── SECURITY.md    
├── requirements.txt
├── config/                     # IDRS configuration file 
│   └── config.yaml
├── src/                        # project source code
│   ├── alert_interface.py       
│   ├── sniffer.py               
│   ├── preprocess.py        
│   ├── rules_analyze.py      
│   └── classify.py              
├── presentations/               # poster, slides, manuscript
│   ├──   ...PDFs              
```

---

### <u>Reseach & System Design</u>

**TL;DR**: *Consumer and FPV drones—including the DJI Neo studied in this project—are frequently vulnerable to attack due to weak passwords, weak encryption, or the absence of security protocols altogether. This project presents an IDRS (Intrusion Detection and Response System), which is a Python-based tool that detects and mitigates two real-world attack vectors identified through months of vulnerability testing: unauthorized Wi-Fi access and deauthentication flooding (a denial-of-service attack). Unlike existing tools such as Kismet, which can detect intrusions but not respond to them, IDRS actively blocks unauthorized devices from connecting to the drone's network. In testing across all attack combinations, IDRS detected 100% of intrusion attempts and prevented all unauthorized Wi-Fi access, with average detection-and-response times of 1–3 seconds.*

Fun Version

**1. Problem**

[Recently, consumer drones have been popping up everywhere](https://www.grandviewresearch.com/industry-analysis/consumer-drone-market) (even my science research teacher has one). People use them for photography, social media, and - my personal favorite - [for racing FPV drones at 90 mph](https://www.youtube.com/watch?v=P25BwtepmUk&pp=ygUQZnB2IGRyb25lIHJhY2luZw%3D%3D) through obstacle courses [like a scene out of the *Planes* Disney movie.](https://www.youtube.com/watch?v=PjyF1r5HkI8) **Unfortunately, these drones are very insecure.** There are many reasons, but I suspect it comes down to cost. If it were cheap and efficient to make these drones secure, there would be no Joseph Park GitHub repo right now. Issues currently plaguing the drone industry are weak passwords, weak encryption, [and some drones who have courageously decided that passwords and encryption are for scared sissy chickens. ](https://medium.com/@swalters/whereve-you-been-flying-your-drone-s-wi-fi-is-telling-everyone-382af45e7198)

**2. Solution**

After a couple of months of vulnerability testing, and after I found some [actual vulnerabilities](https://github.com/JosephPark23/drone-idrs-2025/blob/main/presentations/GMU%20Vulnerability%20Assessment%20Presentation.pdf), I wrote a system - and IDRS - that detects and protects the DJI Neo I studied from different attacks. The assessment and slides explain in more detail the technical components of the vulnerabilities and IDRS, but there are basically two ways the DJI Neo can be compromised: by accessing the Wi-Fi network or through a [DoS called deauthentication flooding](https://en.wikipedia.org/wiki/Wi-Fi_deauthentication_attack). The system, through some Python scripts, detects hacking in both vectors, and can prevent unauthorized Wi-Fi access from unknown devices (more about the deauth later).

**3. Results**

[When testing different combinations of attack vectors](https://github.com/JosephPark23/drone-idrs-2025/blob/main/presentations/AIAA_Park_Drones.pdf) (the access, the deauth, and both), the system succeeded in detecting all attacks and mitigating all Wi-Fi access attempts. The system was able to detect and respond within 1-3 seconds on average, and was generally inefficient compared to the Kismet baseline it was compared to. It should be noted that the Kismet did not, however, have a response functionality, which could reduce its usage and increase efficiency. More on this later.


### IDRS Control Flow Diagram

```mermaid
flowchart TD
    A[DJI Drone Wi-Fi Link] -->|802.11 management frames| B[Sniffer #40;tshark#41;<br/>capture into 1-second windows]
    B --> C[Preprocess:<br/>Extract window statistics]
    C --> D[Rules Engine:<br/>Compare window stats to rules/thresholds]
    D --> E{Attack detected?}
    E -->|No| F[Continue monitoring<br/>next window]
    E -->|Yes| G[Alert Engine:<br/>Display alert on console]
    G --> H{Unrecognized MAC: potential attacker?}
    H -->|Yes| I[Active Response: disconnect potential attacker<br/>aireplay-ng deauth attacker]
    H -->|No| F
    I --> F
    F -.loop.-> B```


---

### <u>Installation & Usage</u>

### *Requirements*

**Hardware**

- A Wi-Fi adapter that supports **monitor mode** and frame injection (e.g., Alfa AWUS036AXML).

- A DJI Neo (or another DJI drone; see Limitations) and its controlling phone.

**System tools**

- `tshark` (for the Wireshark CLI)

- `aircrack-ng` provides `aireplay-ng` and `airmon-ng`

- `iw` or `iwconfig` (optional; for channel locking on Linux)

**Python** 3.10+ with the packages in `requirements.txt`:

```
pyyaml
numpy
pandas
```

---

### Installation

```bash
git clone https://github.com/JosephPark23/drone-idrs-2025.git

cd drone-idrs-2025


# (recommended) venv

python3 -m venv .venv

source .venv/bin/activate



pip install -r requirements.txt
```

Install the system tools (Kali example):

```bash
sudo apt update

sudo apt install tshark aircrack-ng iw
```

---

### Usage

**1. Put your adapter into monitor mode** and note the monitor interface name:

```bash
sudo airmon-ng start wlan0

# creates e.g. wlan0mon
```

**2. Create your config** from the example and fill in your own values:

```bash
cp config/config_example.yaml config/config.yaml
```

Edit `config/config.yaml`:

- `network.drone_mac`: the drone BSSID

- `network.phone_macs`: the controller phone's MAC(s)

- `sniffer.interface`: the monitor interface (e.g., `wlan0mon`)

- `sniffer.bssid`: the same as `drone_mac`

- `sniffer.channel`: if you want to optionally lock to the drone's channel (the Neo commonly uses 149)

**3. Run the IDRS** (root is needed for capture and injection):

```bash
sudo python3 src/alert_interface.py -c config/config.yaml
```

(Add `-v` for verbose logging. Press `Ctrl+C` to stop; a session log is automatically saved to `logs/`.)

---

##### Configuration reference

Rules settings in `config.yaml` (see the file for the full list):

| Setting                             | Meaning                                                      |
| ----------------------------------- | ------------------------------------------------------------ |
| `rules.deauth_threshold`            | Deauth frames targeting an authorized device before alerting |
| `rules.unauth_auth_threshold`       | Auth attempts from an unknown MAC before alerting            |
| `rules.unauth_assoc_threshold`      | Association attempts from an unknown MAC                     |
| `rules.unauth_packet_pct_threshold` | % of window traffic from unknown MACs that triggers an alert |
| `alerts.alert_cooldown`             | Seconds of quiet before an active alert is closed            |
| `sniffer.window_size`               | Analysis window length in seconds                            |

---

### <u>Miscellaneous</u>

### Responsible use

This project is intended for **security research and education on equipment you own or are

explicitly authorized to test.** The active-response feature transmits deauthentication

frames; sending deauth frames against networks or devices you do not own may be **illegal**

in many jurisdictions (for example, the U.S. FCC treats Wi-Fi deauthentication/jamming of

others' networks as unlawful). You are responsible for complying with all applicable laws

and regulations. The authors assume no liability for misuse.

---

### Citation

If you use this work, please cite the paper:

```bibtex
@inproceedings{park2026uav,

  author    = {Park, Joseph and Jablonski, Matthew E.},

  title     = {Real-Time Detection and Active Mitigation of Command-and-Control Link Exploits in Consumer UAVs},

  booktitle = {AIAA Regional Student Conferences},

  year      = {2026},

  doi       = {10.2514/6.2026-114726}

}
```

See also [`CITATION.cff`](CITATION.cff).

---

### AI Usage Disclosure

Generative artificial intelligence was used in the writing of the code for the IDRS files, specifically through the use of the PyCharm IDE's built-in code completion agent, Mellum, and the AI models ChatGPT 4 and Claude Sonnet 5 for checking code, improving elegance and syntax errors, and helping with bugs. AI was also used in the writing of the AIAA Conference Paper (a disclosure can be found in the paper as well). AI was also used to make the Installation, Licenses, and Citations sections and whatnot, because I had no idea how to do those things. 

AI was ***not*** used in creating the project (e.g., idea, research plan, methodology), nor in the design of the IDRS itself, nor in the vulnerability analysis/hacking phase. AI was also ***not*** used in the creation of the vulnerability slides, nor the poster or reconnaissance report. 

---

### Acknowledgments

I would like to thank Dr. Matthew Jablonski and Jad Zarzour for their work in putting up with my late email replies, my questions, my requests for paperwork, and for being incredible teachers and mentors. It was Dr. Jablonski's idea to submit the project to AIAA and all credit is due to him that this project actually got a DOI (I'm shocked myself). At the incorrigible risk of repeating myself, this was an insane opportunity for me. Not many people get to hack drones, and having this sort of experience - that not only teaches you, but gives you the belief, inspiration, and curiosity to pursue your passion further - is life-changing. Finally, a huge thank you to Dr. Duminda Wijesekera for accepting a random stranger's request to join your lab for the summer. George Mason is a lucky place!

---

### License

Released under the MIT License. See [`LICENSE`](LICENSE).
