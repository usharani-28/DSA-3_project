THREAT INTELLIGENCE KILL-CHAIN — LAN DEMO
============================================

This version is a small Node.js LAN prototype designed for a college
presentation.

WHAT MAKES THIS VERSION DIFFERENT
----------------------------------
The login attempts are NOT stored only in the browser.

They are stored centrally in server.js.

Therefore:
- Friend's laptop can submit failed logins.
- Your laptop can submit failed logins.
- Both connect to the SAME server.
- All attempts appear in the central event stream.
- The server records the network source IP it sees.
- After enough attempts, the correlation engine activates the threat chain.

IMPORTANT NETWORK REQUIREMENT
------------------------------
Both laptops must be on the same Wi-Fi/LAN.

The laptop running server.js is the HOST.

RUN
---
1. Install Node.js if it is not already installed.
2. Open CMD in this folder.
3. Run:

   node server.js

4. CMD will show something like:

   Network: http://192.168.1.5:3000

5. On the HOST laptop open:
   http://localhost:3000

6. On the FRIEND laptop open:
   http://192.168.1.5:3000

Replace 192.168.1.5 with the Network address shown by server.js.

WINDOWS FIREWALL
----------------
If Windows asks whether Node.js should be allowed through the firewall,
allow it on Private networks.

If the friend cannot connect, on the HOST laptop you may need to allow
TCP port 3000 through Windows Defender Firewall for a Private network.

DEMO
----
Friend laptop:
- Open the Network URL.
- Enter admin + any wrong password.
- Click LOGIN repeatedly.

Your laptop:
- Open the same Network URL.
- Enter admin + another wrong password.
- Click LOGIN repeatedly.

The central server will accumulate the attempts.

At 5+ failed attempts:
- Risk becomes HIGH.
- DSA pipeline activates.
- Correlation activates.
- Kill-chain stages become visible.
- Final THREAT CHAIN CORRELATED alert appears.

IP NOTE
-------
The server records the IP address of the device connecting to it.

For a same-Wi-Fi demo, you should normally see the friend's LAN IP
(e.g. 192.168.x.x) rather than their public internet IP.

This is an academic simulation. It is not a real intrusion-detection
system and does not perform real attack attribution.
