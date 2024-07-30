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

### Set Attribute Single
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

## Publication
- [source](https://www.rockwellautomation.com/en-us/support/documentation/overview/publication-types.html)
**Publication Types**
Select a publication type to match your information needs.

These are our most common publication types and the typical information you can find in each. To narrow your Literature Library search results, use the Publication Type filter to show only the publications most relevant to your information needs.

**Features, Benefits, and Applications**

- **Application Profile/Customer Success Story (AP)**
  - Demonstrates how our products and services can optimize your industrial operations. Some describe how we helped a specific customer solve an application need.
- **Brochure/Magazine (BR)**
  - Features and benefits for a family of products, group of services, or industry. Best for finding overview information.
- **Profile (PP)**
  - Features and benefits for a single product or service. May include high-level specification and product catalog number information. Best for finding overview information.
- **Sales Promotion (SP)**
  - Includes infographics and eBooks. An infographic provides high-level information in a visual format. An eBook examines topics and challenges that companies may face when working with a specific application.
- **White Paper (WP)**
  - An objective overview or in-depth technical assessment that addresses an architecture, capability, or product technology.

**Technical Specifications and Product Certifications**

- **Certifications (CT)**
  - Product certifications to help you verify that the ratings meet the needs of your application.
- **Selection Guide (SG)**
  - Selection steps and criteria to help you choose among different products to build a system.
- **Technical Data (TD)**
  - Complete specifications of a product family or platform.

**Program**

- **Application Technique (AT)**
  - Programming techniques and configuration recommendations for a specific combination of products or a specific feature or function. Intended for the experienced user.
- **Getting Results (GR)**
  - Describes how to install, navigate, troubleshoot, and effectively use a software product. This publication supplements a comprehensive online help system.
- **Programming Manual (PM)**
  - Guides the developer on how to design, write, and test an application.

**Install and Operate**

- **Dimension Sheet (DS)**
  - Shows product dimensions or mounting templates.
- **Installation Instructions (IN)**
  - Information on how to install, configure (if applicable), and troubleshoot a product.
- **Quick Start (QS)**
  - Basic, task-oriented information on how to install, configure, and operate a set of products or components.
- **Reference Data (RD)**
  - Descriptions of fault codes, alarm codes, parameters, or other highly structured data presented in a spreadsheet format to enable sort and filter capabilities.
- **Reference Manual (RM)**
  - Highly structured and detailed information on product designs, functions, ratings, instructions, or other application requirements. Intended for the experienced user.
- **User Manual (UM)**
  - Instructions for product configuration and use. Can also include installation and troubleshooting information.
- **Wiring Diagram (WD)**
  - Wiring diagrams and connection guidelines. Generally used when the product does not have Installation Instructions or User Manual.

**Publication Number 101**

Do you ever wonder what the characters in our publication numbers mean? These characters provide an at-a-glance view of the type of content in a publication.

![Publication](https://web.archive.org/web/20240303223509im_/https://rockwellautomation.scene7.com/is/image/rockwellautomation/web-search-faq--ra_pub_infographic-1.1140.jpg)