# Calculate JA4 Fingerprint using EdgeWorker

This EdgeWorker calculates the JA4 TLS Client Fingerprint using two input variables and stores the output JA4 in a third variable for use in Property Manager.

- Gets TLS Client Hello data from `PMUSER_TLS_CLIENT_HELLO`
- Gets QUIC Version from `PMUSER_QUIC_VERSION`
- Sets JA4 fingerprint value in `PMUSER_JA4_FINGERPRINT`

## Prerequisites
### CPS
- Add following tag to ESSLINDEX Metadata Extensions, at the Deployment Settings
    - This tag is required to use `AK_CLIENT_HELLO` which contains raw Client Hello data in Base64 encoding
```xml
<save-client-hello>on</save-client-hello> 
```

### Property
- Define Property Variables
    - PMUSER_TLS_CLIENT_HELLO
    - PMUSER_QUIC_VERSION    
    - PMUSER_JA4_FINGERPRINT

- Add an Advanced Behavior to get Client Hello from `AK_CLIENT_HELLO`
```xml
<match:request.type value="CLIENT_REQ" result="true">
  <assign:variable>
    <name>PMUSER_TLS_CLIENT_HELLO</name>
    <value>%(AK_CLIENT_HELLO)</value>
  </assign:variable>
</match:request.type>
```

- Add an Advanced Behavior to get QUIC Version from `AK_QUIC_VERSION`
```xml
<match:request.type value="CLIENT_REQ" result="true">
  <assign:variable>
    <name>PMUSER_QUIC_VERSION</name>
    <value>%(AK_QUIC_VERSION)</value>
  </assign:variable>
</match:request.type>
```

- Add EdgeWorkers Behavior
- Use `PMUSER_JA4_FINGERPRINT` after the EdgeWorkers Behavior

## References
- Overview of the JA4+ family of fingerprints [here](https://blog.foxio.io/ja4+-network-fingerprinting).
- Technical  details on JA4 TLS Client Fingerprinting [here](https://github.com/FoxIO-LLC/ja4/blob/main/technical_details/JA4.md).
- Useful reference implementations in Python, Rust, C (Wireshark plugin) [here](https://github.com/FoxIO-LLC/ja4).
- JA3 fingerprinting using EdgeWorkers example [here](https://github.com/akamai/edgeworkers-examples/tree/master/edgecompute/examples/authentication/ja3-fingerprinting).

![JA4](https://blog.foxio.io/assets/img/2023-09-26/ja4.webp)

## Compatibility
Tested using Chrome 128, Edge 128, Safari 17.6, curl 7.71.1. Both HTTP/2 (TCP) and HTTP/3 (QUIC). Calculated JA4 fingerprints were compared against JA4 fingerprints captured in Wireshark and matched.
