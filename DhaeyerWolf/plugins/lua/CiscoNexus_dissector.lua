--------------------------------------------------------------------------
--
-- Cisco Nexus Protocol Plug-in for Wireshark
--
-- date    : April, 16th 2019
-- author  : Younes Dragoni (@ydragoni)
-- contact : secresearch [ @ ] nozominetworks [ . ] com
--
--------------------------------------------------------------------------

-- initialize wrapper fields
cisco_nexus = Proto ("CiscoNexus_vlan","Cisco Nexus")

-- load 802.1Q Virtual LAN dissector
original_vlan_dissector = DissectorTable.get("ethertype"):get_dissector(0x8100)

-- wrapper main function
function cisco_nexus.dissector (buf, pkt, root)
  -- validate packet length is adequate, otherwise quit
  if buf:len() == 0 then return end
  pkt.cols.protocol = cisco_nexus.name
  
  -- create subtree for Cisco Nexus
  subtree = root:add(cisco_nexus, buf(4))

  -- subscribes ECAT dissector
  original_vlan_dissector:call(buf:range(4,buf:len()-4):tvb(), pkt, subtree)

end

-- Initialization routine
function cisco_nexus.init()
end

-- subscribe for Ethernet packets on type 0x8905.
local eth_table = DissectorTable.get("ethertype")
eth_table:add(0x8905, cisco_nexus)