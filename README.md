# DNS-Spoofer
This tool is used to perform DNS spoofing attacks on target systems

## ⚠ Disclaimer!!

### Use this at your own discretion. The developer *is not responsible* for any misuse of the tool.


**To use this:**

    1. Clone this repository
    2. Run dns_spoof.py
    3. Use ping to spoof the target
    4. Remember to flush the iptables and close apache2 server when finished

**Dependencies:**

    scapy module
    netfilterqueue module
    subprocess module
    

*This is supported only on **UNIX** environment, but can be targetted against **any** domain*
