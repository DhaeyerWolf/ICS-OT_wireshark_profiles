# DNP3 


# Application Layer Function Code
| Hex Value | Name                   | Description                                         | Security Implications                                                                                     |
|-----------|------------------------|-----------------------------------------------------|----------------------------------------------------------------------------------------------------------|
| 0x00      | Confirm                | Acknowledge receipt of application data             | Ensures reliable communication; lack of confirmation may indicate communication issues or replay attacks. |
| 0x01      | Read                   | Request data objects from outstation                | Unauthorized reads may leak sensitive information.                                                        |
| 0x02      | Write                  | Write data objects to outstation                    | Unauthorized writes can alter configuration or operational data, potentially causing system misbehavior.   |
| 0x03      | Select                 | Prepare a control point for operation               | Select before operate ensures a two-step control process, reducing risk of accidental operations.          |
| 0x04      | Operate                | Execute operation on selected control point         | Must be protected to prevent unauthorized control of equipment.                                           |
| 0x05      | Direct Operate         | Directly operate a control point, bypassing select  | Increases risk as it omits the select step, should be secured to prevent misuse.                          |
| 0x06      | Direct Operate No Ack  | Operate a control point directly, no acknowledgment | No response required; high risk if used maliciously, as it might not be logged or noticed immediately.    |
| 0x07      | Immediate Freeze       | Freeze counters without altering values             | Can be used to capture system state for analysis, but unauthorized use could disrupt operational monitoring. |
| 0x08      | Immediate Freeze No Ack| Freeze counters without acknowledgment or altering values | Can be used to capture system state for analysis, but unauthorized use could disrupt operational monitoring. |
| 0x09      | Freeze and Clear       | Freeze counters and reset them                      | Could be used to erase historical data, hindering incident analysis and system monitoring.                |
| 0x0A      | Freeze and Clear No Ack| Freeze counters, reset them, no acknowledgment      | Could be used to erase historical data, hindering incident analysis and system monitoring.                |
| 0x0B      | Freeze With Time       | Freeze counters with a timestamp                    | Useful for synchronized measurements; unauthorized use could be a prelude to coordinated attacks.         |
| 0x0C      | Freeze With Time No Ack| Freeze counters with timestamp, no acknowledgment   | Useful for synchronized measurements; unauthorized use could be a prelude to coordinated attacks.         |
| 0x0D      | Cold Restart           | Restart outstation, re-initializing all hardware and software | Unauthorized restarts can cause service interruptions and loss of volatile data.                        |
| 0x0E      | Warm Restart           | Restart outstation without re-initializing hardware | Less disruptive than a cold restart, but still can be used to interrupt service.                         |
| 0x0F      | Initialize Data        | Initialize application data on the outstation       | Can alter operational parameters, potentially leading to unsafe conditions if misused.                   |
| 0x10      | Initialize Application | Initialize application-specific configurations      | Misuse can lead to misconfiguration and system vulnerabilities.                                          |
| 0x11      | Start Application      | Start application-specific functions                | Could initiate unauthorized processes or enable malicious applications.                                  |
| 0x12      | Stop Application       | Stop application-specific functions                 | Can be used to halt critical monitoring or control functions, potentially leading to unsafe conditions.  |
| 0x13      | Save Configuration     | Save current configuration settings                 | Unauthorized saving of configurations can lock in malicious settings, making them persistent.            |
| 0x14      | Enable Unsolicited     | Enable unsolicited responses from outstation        | If misconfigured, could lead to denial-of-service through response flooding.                             |
| 0x15      | Disable Unsolicited    | Disable unsolicited responses from outstation       | Could be used to prevent alarms or other important notifications from being reported.                    |
| 0x16      | Assign Class           | Assign data objects to a class for reporting        | Misassignment can lead to missed alarms or excessive traffic, depending on the class.                    |
| 0x17      | Delay Measurement      | Measure communication delay                         | Important for timing analysis, but could be used to map network performance for targeted attacks.        |
| 0x18      | Record Current Time    | Record the current time in outstation               | Ensures time synchronization, but incorrect time settings could affect timestamped data and event logging. |
| 0x19      | Open File              | Open a file for reading or writing                  | Unauthorized access could lead to data leakage or alteration.                                            |
| 0x1A      | Close File             | Close a file                                        | Proper file handling is crucial for data integrity; unauthorized closure could disrupt legitimate operations. |
| 0x1B      | Delete File            | Delete a file                                       | Could be used to remove critical firmware or configuration files, potentially causing outstation malfunction. |
| 0x1C      | Get File Information   | Retrieve file attributes                            | Unauthorized access could reveal sensitive information about file contents and system configuration.     |
| 0x1D      | Authenticate File      | Authenticate a file's integrity                     | Ensuring file authenticity is critical for preventing the execution of tampered or malicious code.       |
| 0x1E      | Abort File             | Abort ongoing file operations                       | Could disrupt legitimate updates or data transfers, potentially leaving the system in an inconsistent state. |
| 0x1F      | Activate Configuration | Activate a configuration object                     | Unauthorized activation could implement malicious configurations, affecting system operation.            |
| 0x20      | Authenticate Request   | Request authentication challenge                    | Ensures secure communication; failure to authenticate could indicate an attempted security breach.      |
| 0x21      | Authenticate Error     | Report an authentication error                      | Critical for detecting and responding to authentication failures, which may signify attempted unauthorized access. |
| 0x22      | Response               | Response for solicited messages                     | Responses must be verified to ensure data integrity and to detect replay attacks.                       |
| 0x23      | Unsolicited Response   | Unsolicited response for Class 1/2/3 data           | Must be monitored for unexpected traffic, which could indicate a compromised outstation.                |
| 0x24      | Unknown                | Unknown function code                               | Unknown codes could be indicative of a malfunctioning or compromised device and should be investigated. |
|           |                        | Additional proprietary or future standard function codes | Proprietary codes require vendor-specific knowledge to assess security implications.                |


# Internal Indications
| Filter            | Name                         | Description                                               | Cyber Security Implications                                                                                     |
|-------------------|------------------------------|-----------------------------------------------------------|------------------------------------------------------------------------------------------------------------------|
| dnp3.al.iin.rst   | Device Reset                 | Indicates that the device has been reset.                 | If unexpected, may indicate potential cyber-attack or device malfunction.                                        |
| dnp3.al.iin.dt    | Device trouble.              | General indication that there is a problem with the device. | Could be indicative of a cyber-attack or hardware issue that needs attention.                                   |
| dnp3.al.iin.dol   | Digital Outputs in Local.    | Digital outputs are being controlled locally and not remotely. | May reduce the risk of unauthorized remote operations but indicates loss of remote control.                     |
| dnp3.al.iin.tsr   | Time sync Required.          | The device requires time synchronization.                 | If frequent, may suggest a coordinated attack on time sources or device malfunctions.                            |
| dnp3.al.iin.cls3d | Class 3 data available.      | Class 3 data is available to be retrieved by the master.  | Sudden or unexpected availability might need investigation for unauthorized access.                             |
| dnp3.al.iin.cls2d | Class 2 data available.      | Class 2 data is available to be retrieved by the master.  | Sudden or unexpected availability might need investigation for unauthorized access.                             |
| dnp3.al.iin.cls1d | Class 1 data available.      | Class 1 data is available to be retrieved by the master.  | Sudden or unexpected availability might need investigation for unauthorized access.                             |
| dnp3.al.iin.bmsg  | Broadcast Msg Rx.            | A broadcast message has been received.                    | May be a sign of an attempt to send commands to multiple devices simultaneously.                                |
| dnp3.al.iin.cc    | Configuration corrupt.       | The device's configuration is corrupt and needs to be checked. | Could indicate a cyber-attack aimed at disrupting operations by corrupting configuration files.               |
| dnp3.al.iin.oae   | Operation Already Executing. | An operation is already in progress on the device.        | Multiple operations may indicate a denial-of-service attack.                                                    |
| dnp3.al.iin.ebo   | Event buffer overflow.       | The event buffer has overflowed, and some events may have been lost. | Could be caused by an attack designed to trigger numerous events and overwhelm the system.                 |
| dnp3.al.iin.pioor | Parameters Invalid or Out of Range. | Parameters received are invalid or out of range.       | May be due to misconfiguration or an attempt to cause the device to operate outside safe parameters.            |
| dnp3.al.iin.obju  | Requested Objects Unknown.   | The requested data objects are unknown to the device.     | Could indicate an attempt to probe the device for information or capabilities.                                  |
| dnp3.al.iin.fcni  | Function code not implemented. | The requested function code is not implemented in the device. | Repeated attempts could be seen as probing for device capabilities or could cause unnecessary processing.    |

