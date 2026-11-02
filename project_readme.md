# SDN-Based Zero-Trust Network Access Control

Implementation of an identity-driven network access control architecture using Mininet, Open vSwitch (OVS), and Python low-level socket programming. 

By default, an OpenFlow drop rule blocks access to a protected HTTP service. After successful authentication with a custom TCP authentication server, dynamic flow rules are injected into the OpenFlow 1.3 switch to grant temporary, host-specific access.

## Topology and Addressing

* Switch `s1`: Open vSwitch configured with OpenFlow 1.3
* Client Node `h1`: 10.0.0.1/24
* Client Node `h2`: 10.0.0.2/24
* Auth Server `auth`: 10.0.0.10/24 (TCP port 9000)
* Target Server `target`: 10.0.0.20/24 (HTTP port 80)

## Flow Rule Hierarchy

* Priority 100: Forward authorized client traffic to target port 80 (injected dynamically after login).
* Priority 50: Forward bi-directional traffic on TCP port 9000 (control plane communication with the auth server).
* Priority 50: Forward bi-directional traffic on TCP port 5000 (auxiliary control/management).
* Priority 10: Forward ARP packets for Layer-2 address resolution.
* Priority 0: Drop all other unmatching traffic (default-deny floor).

## Socket Usage

* Server TCP Socket (`auth_server.py`): Listens on 0.0.0.0:9000 using standard BSD sockets. Spawns an independent thread per connection to process concurrent authentication, registration, and user deletion requests.
* Client TCP Socket (`client_gui.py`): Connects to 10.0.0.10:9000 to deliver JSON-formatted credential and control messages.
* UDP Route Probe (`client_gui.py`): Uses a dummy UDP connection toward the authentication host to inspect the kernel routing table and determine the client's own interface IP dynamically without sending packets across the switch.

## Execution Steps

### 1. Requirements

* Ubuntu Linux (or WSL2)
* Mininet
* Open vSwitch (`openvswitch-switch`)
* Python 3 and Tkinter (`python3-tk`)

### 2. Start the Topology

Clean previous Mininet state and start the network:

```bash
sudo mn -c
sudo python3 topo.py
```

### 3. Start Background Daemons

Inside the Mininet CLI:

```bash
mininet> auth python3 auth_server.py &
mininet> target python3 -m http.server 80 &
```

### 4. Verify Default Drop

Confirm that unauthenticated traffic to the target is blocked:

```bash
mininet> h1 curl -m 2 http://10.0.0.20:80
```

The request will time out due to the Priority 0 drop rule.

### 5. Launch Client and Authenticate

Open the client interface for host `h1`:

```bash
mininet> h1 python3 client_gui.py &
```

Log in using an existing credential (`alice` / `pass123`) or register a new user. Upon successful authentication, the server executes `ovs-ofctl add-flow` on switch `s1`.

### 6. Verify Authorized Access and Flow Table

Test connectivity from `h1`:

```bash
mininet> h1 curl -i http://10.0.0.20:80
```

Inspect active switch flows and packet counters:

```bash
mininet> sh ovs-ofctl -O OpenFlow13 dump-flows s1
```

Confirm that host `h2` remains blocked under default isolation:

```bash
mininet> h2 curl -m 2 http://10.0.0.20:80
```

### 7. Revoke Session

Click "Revoke" in the GUI or submit an incorrect password to trigger the penalty lockdown. The Priority 100 flow is removed, and subsequent access attempts from `h1` will drop.

## Repository Contents

* `topo.py`: Mininet network setup script and initial OpenFlow rule configuration.
* `auth_server.py`: Multi-threaded TCP daemon handling user management and dynamic flow injection/removal.
* `client_gui.py`: Tkinter-based client interface with automated OVS flow polling.