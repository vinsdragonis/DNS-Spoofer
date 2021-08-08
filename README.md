# DNS-Spoofer
This tool is used to perform DNS spoofing attacks on target systems

## ⚠ Disclaimer!!

### Use this at your own discretion. The developer *is not responsible* for any misuse of the tool.


**To use this:**

    1. Clone this repository
    2. Run netowrk_scanner.py
    3. Run dns_spoof.py
    4. Use ping to spoof the target
    5. Remember to flush the iptables and close apache2 server when finished

**Dependencies:**

    scapy module
    netfilterqueue module
    

*This is supported only on **UNIX** environment, but can be targetted against **any** domain*

**To allow the victim to access the internet, use the command below before ruuning this tool:**

    echo 1 > /proc/sys/net/ipv4/ip_forward
