# Rockwell specific 
- source: enet-at002_-en-p.pdf (Rockwell Automation Publication ENET-AT002E-EN-P - January 2023)
- source: Various personal observations in pcaps

## Terminology
- Download: Send a program from Workstation to a PLC                  Workstation -> PLC
- Upload: Grab a program from a PLC onto the Workstation              PLC -> Workstation

## Wireshark notes
| service code | Name                                       | notes                                                                                           |
| ------------ | ------------------------------------------ | ----------------------------------------------------------------------------------------------- |
|     0x36     | unkown                                     | unkown                                                                                          |
|     0x37     | I/O Force Activation request               | observetions showed enable I/O request; Force I/O request                                       |
|     0x38     | unkown                                     | unkown                                                                                          |
|     0x4C     | Read Tag                                   | not yet observed, but potentially used during program upload                                    |
|     0x4D     | Write Tag                                  | Has been observed during program Download, add "enip.timeout == 1" to get only the requests     |
|     0x4E     | Read Modify Write                          | Read Modify Write                                                                               |
|     0x50     | unkown                                     | Unkown data that contains (port), configuration data                                            |
|     0x52     | Read Tag Fragmented                        | Read Tag Fragmented                                                                             |
|     0x53     | Write Tag Fragmented                       | Write Tag Fragmented                                                                            |
|     0x54     | unkown                                     | Not yet encountered, however 0x53 & 0x55 exists so probably 0x54 as well                        |
|     0x55     | Get Instance Attribute List                | Get Instance Attribute List                                                                     |


## Protocol structure
| Name         | Description                                                 | Wireshark filter |
|--------------|-------------------------------------------------------------|------------------|
| Service Code | Specifies the operation (e.g., read, write)                 | cip.sc           |
| Class        | Identifies the group of objects targeted by the operation.  | cip.class        |
| Instance     | Specifies the particular object within the class.           | cip.instance     |
| Attribute    | Indicates the specific property or data point to be accessed or modified. | cip.attribute    |

- **Service Code:** The service code is a part of the CIP message that specifies the type of operation to be performed. It defines the action that the client (e.g., a PLC or HMI) is requesting the server (e.g., a sensor or actuator) to execute. Common service codes include read, write, reset, start, stop, etc.
- **Class:** In CIP, a class is a collection of objects that share common characteristics and behaviors. Each class represents a specific type of device or function within the network. For instance, there might be a class for analog input modules, another for digital output modules, and so on. Each class is identified by a unique class ID.
- **Instance:** An instance is a specific occurrence of a class. While a class defines the general characteristics and behaviors, an instance represents a particular object within that class. For example, if you have a class for analog input modules, each individual analog input module on the network would be an instance of that class. Instances are identified by instance IDs.
- **Attribute:** Attributes are specific properties or data points associated with a class or instance. They represent the actual data that can be read or written, such as the current value of a sensor, configuration parameters, or status information. Each attribute is identified by an attribute ID.

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