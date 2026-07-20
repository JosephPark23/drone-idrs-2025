# Security & Responsible Use

## Intended use

This project is provided for **security research and education**. It is designed to be used
**only** on drone hardware and Wi-Fi networks that you **own** or have **explicit, written
authorization** to test.

## Important legal notice

This system includes an **active-response feature** that transmits 802.11 deauthentication
frames to disconnect a device it identifies as unauthorized. Transmitting deauthentication
frames against networks or devices you do not own or are not authorized to test may be
**illegal** in many jurisdictions.

For example, in the United States, the Federal Communications Commission (FCC) treats the
jamming or deauthentication of Wi-Fi networks you do not control as a violation of federal
law, and has issued substantial penalties for it. Other countries have equivalent
restrictions.

**You are solely responsible** for ensuring your use of this software complies with all
applicable local, national, and international laws and regulations. The authors accept no
liability for misuse or for any damage or legal consequences arising from use of this
software.

## Safe testing guidance

- Test only against your own drone and controller, in an isolated environment.
- Where possible, disable the active-response feature when it is not required.
- Do not operate this tool in shared or public RF environments where it could disrupt
  bystanders' networks.

## Reporting a vulnerability

If you discover a security issue in this code, please open an issue or contact the
maintainer directly rather than disclosing it publicly.
<!-- TODO: add a contact email or GitHub handle if you want a private disclosure channel. -->
