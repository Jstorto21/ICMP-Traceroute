# ICMP Traceroute & Ping Utility

A Python-based network diagnostic tool that mimics the functionality of `ping` and `traceroute` using raw ICMP packets.

---

## Features

- Sends ICMP Echo Request packets
- Performs traceroute by incrementing TTL
- Calculates RTT (Round-Trip Time) statistics
- Displays packet loss and response types
- Supports detailed packet validation
- Optional hex dump for debugging

---

## Requirements

- Python 3.6+
- Administrator/root privileges (required for raw sockets)

Run with:
```bash
sudo python3 IcmpHelperLibrary-1.py
```

---

## Usage

Inside the `main()` function, toggle between `ping` and `traceroute` modes:

```python
icmpHelperPing.sendPing("gaia.cs.umass.edu")
icmpHelperPing.traceRoute("gaia.cs.umass.edu")
```

Then run:

```bash
python3 IcmpHelperLibrary-1.py
```

---

## Sample Output

```
TTL=1    RTT=21.7 ms    Type=11  Code=0  (Time Exceeded)    10.0.0.1
TTL=2    RTT=42.3 ms    Type=11  Code=0  (Time Exceeded)    172.16.1.1
TTL=3    RTT=65.8 ms    Type=0   Code=0  (Destination Reached)    192.0.2.1
```

---

## References

- RFC 792: ICMP  
  https://www.rfc-editor.org/rfc/rfc792.html

- IANA ICMP Parameters  
  https://www.iana.org/assignments/icmp-parameters/icmp-parameters.xhtml  
  https://www.iana.org/assignments/icmp-parameters/icmp-parameters.xhtml#icmp-parameters-codes-0  
  https://www.iana.org/assignments/icmp-parameters/icmp-parameters.xhtml#icmp-parameters-codes-3  
  https://www.iana.org/assignments/icmp-parameters/icmp-parameters.xhtml#icmp-parameters-codes-11

- Python `socket` documentation  
  https://docs.python.org/3/library/socket.html

- How is an ICMP packet constructed in Python (Stack Overflow)  
  https://stackoverflow.com/questions/34614893/how-is-an-icmp-packet-constructed-in-python

- Good starting values for min/max variables (Stack Overflow)  
  https://stackoverflow.com/questions/68198688/whats-a-good-starting-value-for-a-min-or-max-variable

- Understanding Traceroute – A concise Python implementation using Scapy (Medium)  
  https://medium.com/@davho/understanding-traceroute-a-concise-guide-python-implementation-using-scapy-9a2221c9a50c

- Ping, Traceroute, Netstat – Red Hat  
  https://www.redhat.com/en/blog/ping-traceroute-netstat

---

## Author

Joseph Storto  
CS 372 — Oregon State University  
GitHub: https://github.com/Jstorto21

---

For educational use. Do not use on unauthorized networks.
