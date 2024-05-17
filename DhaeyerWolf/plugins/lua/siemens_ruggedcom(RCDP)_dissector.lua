--------------------------------------------------------------------------
--
-- Siemens Ruggedcom (RCDP) Protocol Plug-in for Wireshark
--
-- date    : May, 7th 2021
-- author  : Luca Cremona (linkedin: luca--cremona)
-- contact : secresearch [ @ ] nozominetworks [ . ] com
--
--------------------------------------------------------------------------

rcdp_proto = Proto("RCDP", "Siemens RCDP")

-- GENERAL DEFINES
local HEADER_SEPARATOR = 513
local TMP_SEPARATOR = 130
local TMP_SEPARATOR_2 = 129
local FIELD_SEPARATOR = 48
local FIELD_TYPE_1 = 1548
local FIELD_TYPE_2 = 1544

-- RCDP PROTOCOL ID
local RCDP_PID = 0x01e6

-- BYTE INDEXES
local LEN_2ND_POS = 0
local SEQUENCE_N_POS = 4

-- FIELDS LENGTH
local L_LEN_2ND = 2
local L_SEQUENCE_N = 1

-- INIT. FIELDS
local data_data = Field.new("data.data")
local llc_pid = Field.new("llc.pid")


seq_number 		= ProtoField.uint8("rcdp.seq_number", "Sync Number", base.HEX)
direction 		= ProtoField.uint8("Direction", "Direction", base.HEX)
command 		= ProtoField.uint8("Command", "Command", base.HEX)
sequence_n 		= ProtoField.int32("rcdp.sequence_n", "Sequence", base.DEC)
fields_length 	= ProtoField.int32("rcdp.fields_length", "All Fields Length", base.DEC)
content_length 	= ProtoField.int32("rcdp.content_length", "Content Length", base.DEC)
len_2nd 		= ProtoField.int32("rcdp.len_2nd", "Information length", base.DEC)

os_version 		= ProtoField.string("rcdp.os_version", "OS Version", base.ASCII)
boot_version	= ProtoField.string("rcdp.boot_version", "Boot Version", base.ASCII)
serial_num 		= ProtoField.string("rcdp.serial_num", "Serial Number", base.ASCII)
order_code 		= ProtoField.string("rcdp.order_code", "Order Code", base.ASCII)
location 		= ProtoField.string("rcdp.location", "Location", base.ASCII)
contact 		= ProtoField.string("rcdp.contact", "Contact", base.ASCII)
device_name 	= ProtoField.string("rcdp.device_name", "Device Name", base.ASCII)
ip_addr 		= ProtoField.ipv4("rcdp.ip_addr", "IP Address")
gateway 		= ProtoField.ipv4("rcdp.gateway", "Gateway")
mask 			= ProtoField.ipv4("rcdp.mask", "Subnet Mask")
blink_led 		= ProtoField.int32("rcdp.led", "Blink Led", base.DEC)

rcdp_proto.fields = { 	
			seq_number, 
			len_2nd,
			direction,
			content_length,
			sequence_n,
			fields_length,
			command,
			sys_name,
			os_version,
			boot_version,
			serial_num,
			order_code,
			location,
			contact,
			device_name,
			ip_addr,
			gateway,
			mask,
			blink_led
}


function rcdp_proto.dissector(buffer, pinfo, tree)
	length=buffer:len()
	
	if length == 0 then return end
	
	local llc_pid_ex = llc_pid()

	if llc_pid_ex == nil or llc_pid_ex.value ~= RCDP_PID
	then return
	end

	pinfo.cols.protocol = rcdp_proto.name
	
	local buf = data_data().range()
	local buf_len = buf:len()
	local subtree = tree:add(rcdp_proto, buf(0, buf:len()), "RCDP Protocol Data")
	len_2nd_val = buf(LEN_2ND_POS , L_LEN_2ND)

	if len_2nd_val:uint() ~= 0 then
		subtree:add(len_2nd, len_2nd_val)
	else
		subtree:add(len_2nd, len_2nd_val):append_text("  -> Autodiscovery - ping ACK")
	end

	subtree:add(seq_number, buf(SEQUENCE_N_POS , L_SEQUENCE_N))
	
	if(len_2nd_val:uint() > 0) then
		local second_part_start = buf_len - len_2nd_val:uint()
		local iterator = second_part_start
		local dir = buf(iterator,1)

		subtree:add(direction, dir):append_text(" [" .. get_direction(dir:uint()) .. "]")
		iterator = iterator + 1
		local tmp = buf(iterator,1)	

		if (tmp:uint() == TMP_SEPARATOR) then
			subtree:add(command, tmp):append_text(" -> Autodiscovery - Senda Data")
			f_autodiscovery(buf, pinfo, subtree, iterator+1, buf_len)
		elseif (tmp:uint() == TMP_SEPARATOR_2) then
			subtree:add(command, tmp):append_text(" -> Autodiscovery - Request Data")
			f_autodiscovery_req(buf, pinfo, subtree, iterator+1, buf_len)
		else
			f_set_value(buf, pinfo, subtree, iterator, buf_len)
		end
	end
end


function get_direction(value)
	local direction = "UNKNOWN"

	if value == 162 then direction = "RUGGEDCOM -> PC"
	elseif value == 163 then direction = "PC -> RUGGEDCOM"
	elseif value == 160 then direction = "BROADCAST"
	end

	return direction
end

function f_autodiscovery_req (buf, pinfo, subtree, iterator, buf_len)
	local num_bytes = 0
	local tmp_len = 0
	local tmp_id
	
	while buf(iterator,2):uint() ~= HEADER_SEPARATOR do
		iterator = iterator + 1
		num_bytes = num_bytes + 1
	end

	local content_len = buf(iterator-num_bytes, num_bytes)

	if content_len:uint() > 0 then
		subtree:add(content_length, content_len:uint())
	end

	iterator = iterator + 2
	num_bytes = 0
	
	while buf(iterator,2):uint() ~= HEADER_SEPARATOR do
		iterator = iterator + 1
		num_bytes = num_bytes + 1
	end

	local sequence = buf(iterator-num_bytes,num_bytes)

	subtree:add(sequence_n, sequence)
	iterator = iterator + 2

	while buf(iterator,1):uint() ~= TMP_SEPARATOR_2 do
		iterator = iterator + 1
	end

	iterator = iterator + 1
	num_bytes = 0

	while buf(iterator,1):uint() ~= FIELD_SEPARATOR do
		iterator = iterator + 1
		num_bytes = num_bytes + 1
	end

	local fields_len = buf(iterator-num_bytes, num_bytes)

	if fields_len:int() < 0 then
		subtree:add(fields_length, fields_len:uint())
	end
end


function f_autodiscovery (buf, pinfo, subtree, iterator, buf_len) 
	local num_bytes = 0
	local tmp_len = 0
	local tmp_id
	
	while buf(iterator,2):uint() ~= HEADER_SEPARATOR do
		iterator = iterator + 1
		num_bytes = num_bytes + 1
	end

	local content_len = buf(iterator-num_bytes, num_bytes)

	if content_len:uint() > 0 then
		subtree:add(content_length, content_len)
	end

	iterator = iterator + 2
	num_bytes = 0
	
	while buf(iterator,2):uint() ~= HEADER_SEPARATOR do
		iterator = iterator + 1
		num_bytes = num_bytes + 1
	end

	local sequence = buf(iterator-num_bytes,num_bytes)

	subtree:add(sequence_n, sequence)
	iterator = iterator + 2

	while buf(iterator,1):uint() ~= TMP_SEPARATOR do
		iterator = iterator + 1
	end

	iterator = iterator + 1
	num_bytes = 0

	while buf(iterator,1):uint() ~= FIELD_SEPARATOR do
		iterator = iterator + 1
		num_bytes = num_bytes + 1
	end

	local fields_len = buf(iterator-num_bytes, num_bytes)

	if fields_len:int() < 0 then
		subtree:add(fields_length, fields_len)
	end
	
	iterator = iterator + 1

	while (iterator < buf_len) do
		local field_len = buf(iterator, 1)
		iterator = iterator + 1

		if(buf(iterator, 2):uint() == FIELD_TYPE_2) then
			add_field_0608(buf, subtree, iterator)
		else
			add_field_060c(buf, subtree, iterator)
		end

		iterator = iterator + field_len:uint() + 1
	end
end

function f_set_value (buf, pinfo, subtree, iterator, buf_len)
	local num_bytes = 0
	local tmp_len = 0
	local tmp_id
	
	while buf(iterator,2):uint() ~= HEADER_SEPARATOR do
		iterator = iterator + 1
		num_bytes = num_bytes + 1
	end

	local content_len = buf(iterator-num_bytes, num_bytes)
	subtree:add(content_length, content_len)
	iterator = iterator + 2
	num_bytes = 0
	
	while buf(iterator,2):uint() ~= HEADER_SEPARATOR do
		iterator = iterator + 1
		num_bytes = num_bytes + 1
	end

	local sequence = buf(iterator-num_bytes,num_bytes)

	subtree:add(sequence_n, sequence)
	iterator = iterator + 2

	while buf(iterator,1):uint() ~= FIELD_SEPARATOR do
		iterator = iterator + 1
	end

	iterator = iterator + 1
	num_bytes = 0

	while buf(iterator,1):uint() ~= FIELD_SEPARATOR do
		iterator = iterator + 1
		num_bytes = num_bytes + 1
	end

	local fields_len = buf(iterator-num_bytes, num_bytes)
	subtree:add(fields_length, fields_len)

	iterator = iterator + 1

	while (iterator < buf_len) do
		local field_len = buf(iterator, 1)
		iterator = iterator + 1

		if(buf(iterator, 2):uint() == FIELD_TYPE_2) then
			add_field_0608(buf, subtree, iterator)
		else
			add_field_060c(buf, subtree, iterator)
		end
		iterator = iterator + field_len:uint() + 1
	end

end

function add_field_060c (buf, subtree, iterator, buf_len)
	iterator = iterator + 11
	local field_id = buf(iterator,2)
	iterator = iterator + 4
	local field_len = buf(iterator,1)
	iterator = iterator + 1

	if field_id:uint() == 257 then
		if field_len:uint() ~= 0 then
			subtree:add(ip_addr, buf(iterator, field_len:uint()))
		end
	elseif field_id:uint() == 258 then
		if field_len:uint() ~= 0 then
			subtree:add(mask, buf(iterator, field_len:uint()))
		end
	elseif field_id:uint() == 259 then
		if field_len:uint() ~= 0 then
			subtree:add(gateway, buf(iterator, field_len:uint()))
		end
	elseif field_id:uint() == 1030 then
		if field_len:uint() ~= 0 then
			if buf(iterator, field_len:uint()):uint() == 0 then
				subtree:add(blink_led, buf(iterator, field_len:uint())):append_text("  (Not Blinking)")
			else
				subtree:add(blink_led, buf(iterator, field_len:uint())):append_text("  (Blinking)")
			end
		end
	elseif field_id:uint() == 769 then
		subtree:add(serial_num, buf(iterator, field_len:uint()))
	elseif field_id:uint() == 770 then
		subtree:add(boot_version, buf(iterator, field_len:uint()))
	elseif field_id:uint() == 771 then
		subtree:add(os_version, buf(iterator, field_len:uint()))
	end
end

function add_field_0608 (buf, subtree, iterator)
	iterator = iterator + 7
	local field_id = buf(iterator,2)
	iterator = iterator + 4
	local field_len = buf(iterator,1)
	iterator = iterator + 1
	if field_id:uint() == 257 then
		subtree:add(order_code, buf(iterator, field_len:uint()))
	elseif field_id:uint() == 260 then	
		subtree:add(contact, buf(iterator, field_len:uint()))
	elseif field_id:uint() == 261 then
		subtree:add(device_name, buf(iterator, field_len:uint()))
	elseif field_id:uint() == 262 then
		subtree:add(location, buf(iterator, field_len:uint()))
	end
end

-- Register Postdissector
register_postdissector(rcdp_proto)
