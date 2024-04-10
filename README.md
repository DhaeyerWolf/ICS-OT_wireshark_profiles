# NOTICE
THIS IS A FORK OF THE WONDERFUL REPOSITORY: https://github.com/amwalding/wireshark_profiles and other Open Source profiles. However it does not contain ICS/OT specific Wireshark profiles, which I'm creating when the need arises for me. The reason for the fork is to organise it easiliy for myself.

# Wireshark Profiles Repository
Check out this video on the power of Wireshark Profiles:
https://youtu.be/tSzgcEB9f54

# Structure of the Repository
Every contributor has a main folder, in this folder the profiles are listed as .ZIP files (this makes it easy to download if you only want one specific profile).

example:
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

# How To Use The Profiles
1. Simply download the profile you want (they are all zipped).
2. Then from your Wireshark GUI, right click on the lower right corner of the Wireshark GUI - in the Profile box.
3. Then simply select: Import> from zip file, and pick the file from your downloads directory.  Now you can select the newly imported profile!!

# Contribute
Create a pull request with a ZIP file containing your profile. If possible create a profile specific per protocol, if not possible, please clearly state the usecase of the profile in the name of the profile's name.

# Credits
- https://github.com/amwalding/wireshark_profiles
- https://www.cellstream.com/wireshark-profiles-repository/
- @DhaeyerWolf
