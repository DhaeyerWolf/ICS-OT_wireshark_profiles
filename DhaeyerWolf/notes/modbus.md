


# UMAS
## Protocol dissection

### Overview
The basic and normal structure of the protocol. Depending on the UMAS function code the data part can be split up even more.
```
[Modbus Data + Modbus code 90] | [1 byte - UMAS session/pairing key] | [1 byte - UMAS Function code] | [? bytes - Data]
```
From here on out, the modbus data is not displayed as the UMAS protocol is applied after the modbus data & modbus code 90.

### PLC Program Upload (0x31)
```
[1 byte - UMAS session/pairing key] | [1 byte - UMAS Function code] | [2 bytes - 00 01 / 00 10] | [2 bytes - block ID - little Endian] | [2 bytes - block length - little Endian] | [? bytes - Data]
```
- the 3rd part of the protocol, is supposed to always be `00 01`, test however have showed that this can also be `00 10`. It is yet unclear what this means
- The data should be the length fo the defined date in the previous part of the protocol. Everything more than this should be dropped (This has not been verified). 

**Other Notes**
- although it is yet unkown what exactly gets uploaded, it may be a `.stu` file or a `.apx` file.
	- observation shows that the filepath to a `.stu` file is send in one packet (the 4th packet)
	
Online unofficial documentation discribes the following:
```
The upload (computer to PLC) process is quite tricky. The first blocks sent to the PLC must have a specific length:

    Block 1 → 64 bytes (with the first 64 bytes of the APX file)
    Block 2 → 264 bytes (with bytes 65 to 328 of the APX file)
    Block 3 → 64 bytes (with bytes 329 to 373 of the APX file)
    Block 4 → 1014 bytes (if possible)
    Block 5 → 998 bytes (if possible)
    Block 6 → 1008 bytes (if possible)
    Block 7 → 1014 bytes (if possible)

After the 7th block, all blocks are 1022 bytes long (if possible, it depends on negotiation performed during connection. Have a look to sections I and VI for more information). In blocks 4 to 7, if the max packet size is lower than 998, they will be sent with the max packet size. 
```
This is not the same as what I have observed; all my packets were 1012 bytes execpt for the last one (presumably because of the data cutoff)


## Function codes
| Enabled | Protocol | Filter | Description |
|---------|----------|--------|-------------|
| TRUE | Schneider//Program//INIT_COMM | modbus.data[1:2] contains 01 | Initialize a UMAS communication |
| TRUE | Schneider//Program//READ_ID | modbus.data[1:2] contains 02 | Request a PLC ID |
| TRUE | Schneider//Program//READ_PROJECT_INFO | modbus.data[1:2] contains 03 | Read Project Information |
| TRUE | Schneider//Program//READ_PLC_INFO | modbus.data[1:2] contains 04 | Get internal PLC Info |
| TRUE | Schneider//Program//READ_CARD_INFO | modbus.data[1:2] contains 06 | Get internal PLC SD-Card Info |
| TRUE | Schneider//Program//REPEAT | modbus.data[1:2] contains 0A | Sends back data sent to the PLC (used for synchronization) |
| TRUE | Schneider//Program//TAKE_PLC_RESERVATION | modbus.data[1:2] contains 10 | Assign an 'owner' to the PLC |
| TRUE | Schneider//Program//RELEASE_PLC_RESERVATION | modbus.data[1:2] contains 11 | Release the reservation of a PLC |
| TRUE | Schneider//Program//KEEP_ALIVE | modbus.data[1:2] contains 12 | Keep alive message |
| TRUE | Schneider//Program//READ_MEMORY_BLOCK | modbus.data[1:2] contains 20 | Read a memory block of the PLC |
| TRUE | Schneider//Program//READ_VARIABLES | modbus.data[1:2] contains 22 | Read System bits, System Words and Strategy variables |
| TRUE | Schneider//Program//WRITE_VARIABLES | modbus.data[1:2] contains 23 | Write System bits, System Words and Strategy variables |
| TRUE | Schneider//Program//READ_COILS_REGISTERS | modbus.data[1:2] contains 24 | Read coils and holding registers from PLC |
| TRUE | Schneider//Program//WRITE_COILS_REGISTERS | modbus.data[1:2] contains 25 | Write coils and holding registers into PLC |
| TRUE | Schneider//Program//INITIALIZE_UPLOAD | modbus.data[1:2] contains 30 | Initialize Strategy upload (copy from engineering PC to PLC) |
| TRUE | Schneider//Program//UPLOAD_BLOCK | modbus.data[1:2] contains 31 | Upload (copy from engineering PC to PLC) a strategy block to the PLC |
| TRUE | Schneider//Program//END_STRATEGY_UPLOAD | modbus.data[1:2] contains 32 | Finish strategy Upload (copy from engineering PC to PLC) |
| TRUE | Schneider//Program//INITIALIZE_UPLOAD | modbus.data[1:2] contains 33 | Initialize Strategy download (copy from PLC to engineering PC) |
| TRUE | Schneider//Program//DOWNLOAD_BLOCK | modbus.data[1:2] contains 34 | Download (copy from PLC to engineering PC) a strategy block |
| TRUE | Schneider//Program//END_STRATEGY_DOWNLOAD | modbus.data[1:2] contains 35 | Finish strategy Download (copy from PLC to engineering PC) |
| TRUE | Schneider//Program//READ_ETH_MASTER_DATA | modbus.data[1:2] contains 39 | Read Ethernet Master Data |
| TRUE | Schneider//Program//START_PLC | modbus.data[1:2] contains 40 | Starts the PLC |
| TRUE | Schneider//Program//STOP_PLC | modbus.data[1:2] contains 41 | Stops the PLC |
| TRUE | Schneider//Program//MONITOR_PLC | modbus.data[1:2] contains 50 | Monitors variables, Systems bits and words |
| TRUE | Schneider//Program//CHECK_PLC | modbus.data[1:2] contains 58 | Check PLC Connection status |
| TRUE | Schneider//Program//READ_IO_OBJECT | modbus.data[1:2] contains 70 | Read IO Object |
| TRUE | Schneider//Program//WRITE_IO_OBJECT | modbus.data[1:2] contains 71 | Write IO Object |
| TRUE | Schneider//Program//GET_STATUS_MODULE | modbus.data[1:2] contains 73 | Get Status Module |


# sources
## UMAS protocol
- https://lirasenlared.blogspot.com/2017/08/the-unity-umas-protocol-part-i.html
- https://lirasenlared.blogspot.com/2017/08/the-unity-umas-protocol-part-ii.html
- https://lirasenlared.blogspot.com/2017/08/the-unity-umas-protocol-part-iii.html
- https://lirasenlared.blogspot.com/2017/08/the-unity-umas-protocol-part-iv.html
