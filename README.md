# NOTICE
THIS IS A FORK OF THE WONDERFUL REPOSITORY: https://github.com/amwalding/wireshark_profiles and other Open-Source profiles. However, it does not contain ICS/OT-specific Wireshark profiles, which I create when the need arises for me. The reason for the fork is to organize it easily for myself.

# Wireshark Profiles Repository
Check out this video on the power of Wireshark Profiles:
https://youtu.be/tSzgcEB9f54

# Structure of the Repository
Every contributor has a main folder; in this folder, the profiles are listed as .ZIP files (this makes it easy to download if you only want one specific profile).

Example:
```
root
├── DhaeyerWolf
│   └── Profile1.zip
│   └── Profile2.zip
│   └── Profile3.zip
│   └── Profile4.zip
└── amwalding
    └── Profile1.zip
    └── Profile2.zip
    └── Profile3.zip
    └── Profile4.zip
```

# How to Use the Profiles
1. Simply download the profile you want (they are all zipped).
2. Then from your Wireshark GUI, right click on the lower right corner of the Wireshark GUI - in the Profile box.
3. Then simply select: Import> from zip file, and pick the file from your downloads directory.  Now you can select the newly imported profile!!

# Plugins folder
There it is possible that there is a "plugins" folder in some of the repositories. This contains plugins (e.g. additional dissectors) for wireshark. The files in this folder should be placed in the wireshark plugins folder

On Windows:
- For Wireshark portable: `[Install location]/App/Wireshark/plugins`. (for easy use you can just put the whole plugins folder in the `/App/Wireshark/` folder, it will automatically merge the plugins folder.
- The personal plugin folder is %APPDATA%\Wireshark\plugins. (source: https://www.wireshark.org/docs/wsug_html_chunked/ChPluginFolders.html)
- The global plugin folder is WIRESHARK\plugins. (source: https://www.wireshark.org/docs/wsug_html_chunked/ChPluginFolders.html)

On Unix-like systems:
- The personal plugin folder is ~/.local/lib/wireshark/plugins. (source: https://www.wireshark.org/docs/wsug_html_chunked/ChPluginFolders.html)
If you are running on macOS and Wireshark is installed as an application bundle, the global plugin folder is %APPDIR%/Contents/PlugIns/wireshark, otherwise it’s INSTALLDIR/lib/wireshark/plugins. (source: https://www.wireshark.org/docs/wsug_html_chunked/ChPluginFolders.html)

An example of this folder structure can be:
```
plugins
└── lua
    └── script1.lua
```

# Contribute
Create a pull request with a ZIP file containing your profile. If possible, create a profile specific to the protocol; if not possible, please clearly state the use case of the profile in the name of the profile's name.

# Credits
- https://github.com/amwalding/wireshark_profiles
- https://www.cellstream.com/wireshark-profiles-repository/
- @DhaeyerWolf
- https://github.com/biero-el-corridor/Wireshark-UMAS-Modicon-M340-protocol/blob/main/modbus-umas-schneider.lua

# Protocols
The following is a list of the protocols I want to create Wireshark profiles for. Some of them may already be implemented; others are still in a "Work In Progress (WIP)" phase.
- [x] S7Comm
- [x] Profinet
- [x] Modbus TCP/UDP
- [x] OPC-UA
- [x] BACnet
- [x] Ethernet/IP: Common Industrial Protocol (CIP™)
- [x] DNP3
- [ ] MQTT
- [ ] IEC 104