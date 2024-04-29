# OPCUA
## NodeId Identifier Numeric:
#### Session Services
##### CreateSession
- Request: opcua.servicenodeid.numeric == 461
- Response: opcua.servicenodeid.numeric == 464

##### ActivateSession
- Request: opcua.servicenodeid.numeric == 467
- Response: opcua.servicenodeid.numeric == 470

##### CloseSecureChannel
- Request: opcua.servicenodeid.numeric == 452

### Secure Channel Services
##### OpenSecureChannel
- Request: opcua.servicenodeid.numeric == 446
- Response: opcua.servicenodeid.numeric == 449

### Node Management Services
##### Browse
- Request: opcua.servicenodeid.numeric == 527
- Response: opcua.servicenodeid.numeric == 530

##### BrowseNext
- Request: opcua.servicenodeid.numeric == 533
- Response: opcua.servicenodeid.numeric == 536

### Attribute Services
##### Read
- Request: opcua.servicenodeid.numeric == 631
- Response: opcua.servicenodeid.numeric == 634

##### Write
- Request: opcua.servicenodeid.numeric == 673
- Response: opcua.servicenodeid.numeric == 676

### Subscription Services
##### Publish
- Request: opcua.servicenodeid.numeric == 826
- Response: opcua.servicenodeid.numeric == 829

### Discovery Services
##### GetEndpoints
- Request: opcua.servicenodeid.numeric == 428
- Response: opcua.servicenodeid.numeric == 431


## MSG types
- OPN - OpenSecureChannel message
- MSG - UA Secure Conversation Message
- HEL - Hello message
- ACK - Acknowledge message
- CLO - CloseSecureChannel message

**Typical flow of a conversation:**
- Client HEL -> # hello message
- Server ACK <- # Acknowledge hello message
- Client OPN -> # request security poicy (?)
- Server OPN <- # confirms request
- Client MSG -> # requests opc.tcp server (uri)
- Server MSG <- # replies with information
- MSG repeat