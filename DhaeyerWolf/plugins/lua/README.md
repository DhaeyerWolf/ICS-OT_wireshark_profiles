# 
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

# Credits
- @DhaeyerWolf
- https://github.com/biero-el-corridor/Wireshark-UMAS-Modicon-M340-protocol/blob/main/modbus-umas-schneider.lua