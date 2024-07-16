# Rockwell specific 
- source: enet-at002_-en-p.pdf (Rockwell Automation Publication ENET-AT002E-EN-P - January 2023)

## Protocol structure
- Service Code (cip.sc)
- class
- instance
- attribute

### Set Attribute Signle
| Field | value |
| ----- | ----- |
| Service Code | 0x10 |

### DisableSocket
| Field | value |
| ----- | ----- |
| Service Code | 0x10 |
| Class | 0x342 |
| instance | 0 |
| Attribute | 0x9 |

### CreateSocket
| Field | value |
| ----- | ----- |
| Service Code | 0x4b |
| Class | 0x342 |
| instance | 0 |
| Attribute | 0x0 |

MSG source length: Specify the size of the user-defined structure for the source element. In this example, CreateParams is 12 bytes.

### OpenConnection
| Field | value |
| ----- | ----- |
| Service Code | 0x4c |
| Class | 0x342 |
| instance | from Socket Create |
| Attribute | 0x0 |

MSG source length: specify 8 bytes (timeout + AddrLen) + number of characters in destination address

### AcceptConnection
| Field | value |
| ----- | ----- |
| Service Code | 0x50 |
| Class | 0x342 |
| instance | from Socket Create |
| Attribute | 0x0 |

MSG source length: Specify 4 bytes (Timeout).

### ReadSocket
| Field | value |
| ----- | ----- |
| Service Code | 0x4d |
| Class | 0x342 |
| instance | see instance ??? |
| Attribute | 0x0 |

This service uses the instance that is returned from the CreateConnection service. However, when accepting a connection via the
AcceptConnection service, use the instance that is returned from this AcceptConnection service as the ReadSocket instance

MSG source length: Specify 8 bytes (Timeout + BufLen).

### WriteSocket
| Field | value |
| ----- | ----- |
| Service Code | 0x4e |
| Class | 0x342 |
| instance | see instance ??? |
| Attribute | 0x0 |

This service uses the instance that is returned from the CreateConnection service. However, when accepting a connection via the
AcceptConnection service, use the instance that is returned from this AcceptConnection service as the WriteSocket instance.

MSG source length: Specify 16 bytes (Timeout + Addr + BufLen) + number of bytes to write.

### DeleteSocket
| Field | value |
| ----- | ----- |
| Service Code | 0x4f |
| Class | 0x342 |
| instance | from Socket Create|
| Attribute | 0x0 |

MSG source length: Specify 0 bytes 

### DeleteAllSockets
| Field | value |
| ----- | ----- |
| Service Code | 0x51 |
| Class | 0x342 |
| instance | 0 |
| Attribute | 0x0 |

MSG source length: Specify 0 bytes 

### ClearLog
| Field | value |
| ----- | ----- |
| Service Code | 0x52 |
| Class | 0x342 |
| instance | 0 |
| Attribute | 0x0 |

MSG source length: Specify 0 bytes 

### JoinMulticastAddress
| Field | value |
| ----- | ----- |
| Service Code | 0x53 |
| Class | 0x342 |
| instance | from Socket Create |
| Attribute | 0x0 |

MSG source length: Specify 8 bytes 

### DropMulticastAddress
| Field | value |
| ----- | ----- |
| Service Code | 0x54 |
| Class | 0x342 |
| instance | from Socket Create |
| Attribute | 0x0 |

MSG source length: Specify 8 bytes 