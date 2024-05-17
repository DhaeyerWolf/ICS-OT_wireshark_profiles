--------------------------------------------------------------------------
--
-- Mitsubishi Electric MELSOFT Protocol Plug-in for Wireshark
-- Specifically designed for the detection of CVE-2021-20594, CVE-2021-20597, CVE-2021-20598, CVE-2021-20599, NN-2021-0019
-- 
-- date    : November, 15th 2023
-- author  : Andrea Palanca, Ivan Speziale
-- contact : labs [ @ ] nozominetworks [ . ] com
--
--------------------------------------------------------------------------

-- Helper functions

function setDefault(t, d) -- Sets default value of table
    local mt = {__index = function () return d end}
    setmetatable(t, mt)
end

-- Base dissector

proto_melsoft = Proto("melsoft","Mitsubishi Electric MELSOFT Protocol")

base_protofields =
{
    other_magic_bytes = ProtoField.uint16("melsoft.other.magic_bytes", "Magic Bytes", base.HEX)
}

proto_melsoft.fields = base_protofields

req_resp_table = DissectorTable.new("melsoft.req_resp_table", "melsoft.req_resp_table", ftypes.UINT16, base.HEX, melsoft) -- Main children table containing only the relevant request and response protocols

function proto_melsoft.dissector(buffer, pinfo, tree)
    if buffer:len() < 2 then
        return false
    end
    pinfo.cols.protocol = proto_melsoft.name
    local early_magic_bytes_value = buffer(0, 2):uint()
    local child = req_resp_table:get_dissector(early_magic_bytes_value)
    if child ~= nil then
        child(buffer, pinfo, tree)
    else
        local root = tree:add(proto_melsoft, buffer(), "Mitsubishi Electric MELSOFT Protocol")
        local subtree = root:add(proto_melsoft, buffer(), "Other MELSOFT Packet")
        pinfo.cols.info = "Other MELSOFT Packet"
    end
end

local tcp_port = DissectorTable.get("tcp.port")
tcp_port:add(5007, proto_melsoft)

-- Known magic bytes

magic_bytes = {
    [0x5701] = "MELSOFT Request",
    [0xd700] = "MELSOFT Response"
}

-- Known command codes

command_codes = {
    [0x0121] = "Open Initial",
    [0x0131] = "Username Login",
    [0x0132] = "Password Login",
    [0x0133] = "Read User Information from PLC A",
    [0x0134] = "Read User Information from PLC B",
    [0x0150] = "Safety Run Mode Read",
    [0x0410] = "Modify Value",
    [0x1001] = "Remote Control Run",
    [0x1002] = "Remote Control Stop",
    [0x1003] = "Remote Control Pause",
    [0x1006] = "Remote Reset Ex",
    [0x1120] = "Safety Run Mode Change",
    [0x1133] = "User Information Registration",
    [0x1859] = "File List Read",
    [0x1868] = "File Read",
    [0x1869] = "File Write"
}
setDefault(command_codes, "")

-- Known Ethernet footer parameter types

ethftr_parameter_types = {
    [0x42] = "Authorization Token",
    [0x81] = "Command Data CRC32",
    [0x82] = "Command Header Type + Command Data + Ethernet Footer CRC32"
}

-- Known access levels

access_levels = {
    [0x0001] = "Administrators",
    [0x1000] = "Developers",
    [0x0800] = "Assistant Developers",
    [0x0100] = "Users"
}

-- Request dissector

proto_melsoft_req = Proto("melsoft.req","Mitsubishi Electric MELSOFT Protocol - " .. magic_bytes[0x5701])

req_protofields =
{
    magic_bytes = ProtoField.uint16("melsoft.req.magic_bytes", "Magic Bytes", base.HEX, magic_bytes),
    sequence_number = ProtoField.uint8("melsoft.req.sequence_number", "Sequence Number", base.HEX),
    network_number = ProtoField.uint8("melsoft.req.network_number", "Network Number", base.HEX),
    unit_number = ProtoField.uint8("melsoft.req.unit_number", "Unit Number", base.HEX),
    io_number = ProtoField.uint16("melsoft.req.io_number", "I/O Number", base.HEX),
    cmdhdr_cmddata_ethftr_size = ProtoField.uint16("melsoft.req.cmdhdr_cmddata_ethftr_size", "Command Header + Command Data + Ethernet Footer Size", base.DEC),
    cmdhdr_type = ProtoField.uint8("melsoft.req.cmdhdr_type", "Command Header Type", base.HEX),
    cmdhdr_remaining_size = ProtoField.uint8("melsoft.req.cmdhdr_remaining_size", "Command Header Remaining Size", base.DEC),
    command_code = ProtoField.uint16("melsoft.req.command_code", "Command Code", base.HEX, command_codes),
    packet_reference = ProtoField.uint16("melsoft.req.packet_reference", "Packet Reference", base.HEX),
    cmddata_remaining_size = ProtoField.uint16("melsoft.req.cmddata_remaining_size", "Command Data Remaining Size", base.DEC),
    cmddata_payload = ProtoField.bytes("melsoft.req.cmddata_payload", "Payload"),
    ethftr_size = ProtoField.uint16("melsoft.req.ethftr_size", "Ethernet Footer Size", base.DEC),
    ethftr_no_of_parameters = ProtoField.uint8("melsoft.req.ethftr_no_of_parameters", "Number of Parameters", base.DEC),
    ethftr_parameter_type = ProtoField.uint8("melsoft.req.ethftr_parameter_type", "Parameter Type", base.HEX, ethftr_parameter_types),
    ethftr_parameter_size = ProtoField.uint8("melsoft.req.ethftr_parameter_size", "Parameter Size", base.DEC),
    ethftr_parameter_value = ProtoField.bytes("melsoft.req.ethftr_parameter_value", "Parameter Value")
}

proto_melsoft_req.fields = req_protofields

req_fields =
{
    command_code_field = Field.new("melsoft.req.command_code"),
    ethftr_no_of_parameters_field = Field.new("melsoft.req.ethftr_no_of_parameters")
}

req_experts =
{
    request_with_authorization_token = ProtoExpert.new("melsoft.req.request_with_authorization_token.expert", "Request with authorization token - May be abused to exploit CVE-2021-20599", expert.group.SECURITY, expert.severity.NOTE)
}

proto_melsoft_req.experts = req_experts

req_commands_table = DissectorTable.new("melsoft.req.req_commands_table", "melsoft.req.req_commands_table", ftypes.UINT16, base.HEX, melsoft_req) -- Children table for dissecting the various command codes in requests

function proto_melsoft_req.dissector(buffer, pinfo, tree)
    local root = tree:add(proto_melsoft, buffer(), "Mitsubishi Electric MELSOFT Protocol")
    local req = root:add(proto_melsoft_req, buffer(), magic_bytes[0x5701])
    pinfo.cols.info = magic_bytes[0x5701]
    -- Ethernet header
    local ethernet_header = req:add(proto_melsoft_req, buffer(0, 0x15), "Ethernet Header")
    ethernet_header:add(req_protofields["magic_bytes"], buffer(0, 2))
    ethernet_header:add(req_protofields["sequence_number"], buffer(2, 1))
    ethernet_header:add(req_protofields["network_number"], buffer(9, 1))
    ethernet_header:add(req_protofields["unit_number"], buffer(0xa, 1))
    ethernet_header:add(req_protofields["io_number"], buffer(0xb, 2))
    ethernet_header:add_le(req_protofields["cmdhdr_cmddata_ethftr_size"], buffer(0x13, 2))
    -- Command header
    local command_header_starting_byte = 0x15
    local command_header = req:add(proto_melsoft_req, buffer(command_header_starting_byte, 0x18), "Command Header")
    command_header:add(req_protofields["cmdhdr_type"], buffer(command_header_starting_byte+0, 1))
    command_header:add(req_protofields["cmdhdr_remaining_size"], buffer(command_header_starting_byte+2, 1))
    -- Command data
    local cmddata_starting_byte = 0x15+0x18
    local early_cmddata_remaining_size_value = buffer(cmddata_starting_byte+4, 2):le_uint()
    local command_data = req:add(proto_melsoft_req, buffer(cmddata_starting_byte, 6+early_cmddata_remaining_size_value), "Command Data")
    command_data:add(req_protofields["command_code"], buffer(cmddata_starting_byte, 2))
    command_data:add_le(req_protofields["packet_reference"], buffer(cmddata_starting_byte+2, 2))
    command_data:add_le(req_protofields["cmddata_remaining_size"], buffer(cmddata_starting_byte+4, 2))
    local command_code_value = req_fields["command_code_field"]()()
    pinfo.cols.info = magic_bytes[0x5701] .. " - 0x" .. string.format("%X", command_code_value) .. " " .. command_codes[command_code_value]
    local child = req_commands_table:get_dissector(command_code_value)
    if child ~= nil then
        child(buffer, pinfo, command_data)
    else
        command_data:add(req_protofields["cmddata_payload"], buffer(cmddata_starting_byte+6, early_cmddata_remaining_size_value))
    end
    -- Ethernet Footer
    local ethernet_footer_starting_byte = 0x15+0x18+6+early_cmddata_remaining_size_value
    local ethernet_footer = req:add(proto_melsoft_req, buffer(ethernet_footer_starting_byte), "Ethernet Footer")
    ethernet_footer:add_le(req_protofields["ethftr_size"], buffer(ethernet_footer_starting_byte, 2))
    ethernet_footer:add(req_protofields["ethftr_no_of_parameters"], buffer(ethernet_footer_starting_byte+2, 1))
    local ethftr_no_of_parameters_value = req_fields["ethftr_no_of_parameters_field"]()()
    local parameter_sizes = {}
    for i=0,ethftr_no_of_parameters_value-1
    do
        ethernet_footer:add(req_protofields["ethftr_parameter_type"], buffer(ethernet_footer_starting_byte+3+i*2, 1))
        if buffer(ethernet_footer_starting_byte+3+i*2, 1):uint() == 0x42 then
            ethernet_footer:add_proto_expert_info(req_experts["request_with_authorization_token"])
        end
        ethernet_footer:add(req_protofields["ethftr_parameter_size"], buffer(ethernet_footer_starting_byte+3+i*2+1, 1))
        table.insert(parameter_sizes, buffer(ethernet_footer_starting_byte+3+i*2+1, 1):uint())
    end
    for i=1,ethftr_no_of_parameters_value -- Index starts at 1 to correctly access table values (in Lua, first element in a table has index 1)
    do
        local bytes_read = 0
        for j=1,i-1
        do
            bytes_read = bytes_read + parameter_sizes[j]
        end
        ethernet_footer:add(req_protofields["ethftr_parameter_value"], buffer(ethernet_footer_starting_byte+3+ethftr_no_of_parameters_value*2+bytes_read, parameter_sizes[i]))
    end
end

DissectorTable.get("melsoft.req_resp_table"):add(0x5701, proto_melsoft_req)

-- Response dissector

proto_melsoft_resp = Proto("melsoft.resp","Mitsubishi Electric MELSOFT Protocol - " .. magic_bytes[0xd700])

resp_protofields =
{
    magic_bytes = ProtoField.uint16("melsoft.resp.magic_bytes", "Magic Bytes", base.HEX, magic_bytes),
    sequence_number = ProtoField.uint8("melsoft.resp.sequence_number", "Sequence Number", base.HEX),
    cmdhdr_cmddata_ethftr_size = ProtoField.uint16("melsoft.resp.cmdhdr_cmddata_ethftr_size", "Command Header + Command Data + Ethernet Footer Size", base.DEC),
    cmdhdr_type = ProtoField.uint8("melsoft.resp.cmdhdr_type", "Command Header Type", base.HEX),
    cmdhdr_remaining_size = ProtoField.uint8("melsoft.resp.cmdhdr_remaining_size", "Command Header Remaining Size", base.DEC),
    status = ProtoField.uint16("melsoft.resp.status", "Status", base.HEX),
    command_code = ProtoField.uint16("melsoft.resp.command_code", "Command Code", base.HEX, command_codes),
    packet_reference = ProtoField.uint16("melsoft.resp.packet_reference", "Packet Reference", base.HEX),
    cmddata_remaining_size = ProtoField.uint16("melsoft.resp.cmddata_remaining_size", "Command Data Remaining Size", base.DEC),
    cmddata_payload = ProtoField.bytes("melsoft.resp.cmddata_payload", "Payload"),
    ethftr_size = ProtoField.uint16("melsoft.resp.ethftr_size", "Ethernet Footer Size", base.DEC),
    ethftr_no_of_parameters = ProtoField.uint8("melsoft.resp.ethftr_no_of_parameters", "Number of Parameters", base.DEC),
    ethftr_parameter_type = ProtoField.uint8("melsoft.resp.ethftr_parameter_type", "Parameter Type", base.HEX, ethftr_parameter_types),
    ethftr_parameter_size = ProtoField.uint8("melsoft.resp.ethftr_parameter_size", "Parameter Size", base.DEC),
    ethftr_parameter_value = ProtoField.bytes("melsoft.resp.ethftr_parameter_value", "Parameter Value")
}

proto_melsoft_resp.fields = resp_protofields

resp_fields =
{
    command_code_field = Field.new("melsoft.resp.command_code"),
    ethftr_no_of_parameters_field = Field.new("melsoft.resp.ethftr_no_of_parameters")
}

resp_commands_table = DissectorTable.new("melsoft.resp.resp_commands_table", "melsoft.resp.resp_commands_table", ftypes.UINT16, base.HEX, melsoft_resp) -- Children table for dissecting the various command codes in responses

function proto_melsoft_resp.dissector(buffer, pinfo, tree)
    local root = tree:add(proto_melsoft, buffer(), "Mitsubishi Electric MELSOFT Protocol")
    local resp = root:add(proto_melsoft_resp, buffer(), magic_bytes[0xd700])
    pinfo.cols.info = magic_bytes[0xd700]
    -- Ethernet header
    local ethernet_header = resp:add(proto_melsoft_resp, buffer(0, 0x15), "Ethernet Header")
    ethernet_header:add(resp_protofields["magic_bytes"], buffer(0, 2))
    ethernet_header:add(resp_protofields["sequence_number"], buffer(2, 1))
    ethernet_header:add_le(resp_protofields["cmdhdr_cmddata_ethftr_size"], buffer(0x13, 2))
    -- Command header
    local command_header_starting_byte = 0x15
    local command_header = resp:add(proto_melsoft_resp, buffer(command_header_starting_byte, 0x1a), "Command Header")
    command_header:add(resp_protofields["cmdhdr_type"], buffer(command_header_starting_byte+0, 1))
    command_header:add(resp_protofields["cmdhdr_remaining_size"], buffer(command_header_starting_byte+2, 1))
    command_header:add(resp_protofields["status"], buffer(command_header_starting_byte+4, 2))
    -- Command data
    local cmddata_starting_byte = 0x15+0x1a
    local early_cmddata_remaining_size_value = buffer(cmddata_starting_byte+4, 2):le_uint()
    local command_data = resp:add(proto_melsoft_resp, buffer(cmddata_starting_byte, 6+early_cmddata_remaining_size_value), "Command Data")
    command_data:add(resp_protofields["command_code"], buffer(cmddata_starting_byte, 2))
    command_data:add_le(resp_protofields["packet_reference"], buffer(cmddata_starting_byte+2, 2))
    command_data:add_le(resp_protofields["cmddata_remaining_size"], buffer(cmddata_starting_byte+4, 2))
    local command_code_value = resp_fields["command_code_field"]()()
    pinfo.cols.info = magic_bytes[0xd700] .. " - 0x" .. string.format("%X", command_code_value) .. " " .. command_codes[command_code_value]
    local child = resp_commands_table:get_dissector(command_code_value)
    if child ~= nil then
        child(buffer, pinfo, command_data)
    else
        command_data:add(resp_protofields["cmddata_payload"], buffer(cmddata_starting_byte+6, early_cmddata_remaining_size_value))
    end
    -- Ethernet Footer
    local ethernet_footer_starting_byte = 0x15+0x1a+6+early_cmddata_remaining_size_value
    local ethernet_footer = resp:add(proto_melsoft_resp, buffer(ethernet_footer_starting_byte), "Ethernet Footer")
    ethernet_footer:add_le(resp_protofields["ethftr_size"], buffer(ethernet_footer_starting_byte, 2))
    ethernet_footer:add(resp_protofields["ethftr_no_of_parameters"], buffer(ethernet_footer_starting_byte+2, 1))
    local ethftr_no_of_parameters_value = resp_fields["ethftr_no_of_parameters_field"]()()
    local parameter_sizes = {}
    for i=0,ethftr_no_of_parameters_value-1
    do
        ethernet_footer:add(resp_protofields["ethftr_parameter_type"], buffer(ethernet_footer_starting_byte+3+i*2, 1))
        ethernet_footer:add(resp_protofields["ethftr_parameter_size"], buffer(ethernet_footer_starting_byte+3+i*2+1, 1))
        table.insert(parameter_sizes, buffer(ethernet_footer_starting_byte+3+i*2+1, 1):uint())
    end
    for i=1,ethftr_no_of_parameters_value -- Index starts at 1 to correctly access table values (in Lua, first element in a table has index 1)
    do
        local bytes_read = 0
        for j=1,i-1
        do
            bytes_read = bytes_read + parameter_sizes[j]
        end
        ethernet_footer:add(resp_protofields["ethftr_parameter_value"], buffer(ethernet_footer_starting_byte+3+ethftr_no_of_parameters_value*2+bytes_read, parameter_sizes[i]))
    end
end

DissectorTable.get("melsoft.req_resp_table"):add(0xd700, proto_melsoft_resp)

-- Command data dissectors. Currently, only dissectors relevant for the detection of CVE-2021-20594, CVE-2021-20597, CVE-2021-20598, NN-2021-0019 are supported

-- Username login

proto_melsoft_req_username_login = Proto("melsoft.req.username_login","Mitsubishi Electric MELSOFT Protocol - " .. magic_bytes[0x5701] .. " - Username Login")

req_username_login_protofields =
{
    username = ProtoField.string("melsoft.req.username_login.username", "Username", base.UNICODE),
}

proto_melsoft_req_username_login.fields = req_username_login_protofields

req_username_login_experts =
{
    username_login_request = ProtoExpert.new("melsoft.req.username_login.username_login_request.expert", "Username Login request - May be legitimate or an attempt to exploit CVE-2021-20594", expert.group.SECURITY, expert.severity.NOTE)
}

proto_melsoft_req_username_login.experts = req_username_login_experts

function proto_melsoft_req_username_login.dissector(buffer, pinfo, tree)
    local cmddata_starting_byte = 0x15+0x18
    local cmddata_remaining_size_value = buffer(cmddata_starting_byte+4, 2):le_uint()
    local username_login_request = tree:add(proto_melsoft_req_username_login, buffer(cmddata_starting_byte+6, cmddata_remaining_size_value), "Username Login Request")
    username_login_request:add(req_username_login_protofields["username"], buffer(cmddata_starting_byte+6, 0x28), buffer(cmddata_starting_byte+6, 0x28):le_ustring())
    username_login_request:add_proto_expert_info(req_username_login_experts["username_login_request"])
end

DissectorTable.get("melsoft.req.req_commands_table"):add(0x0131, proto_melsoft_req_username_login)

proto_melsoft_resp_username_login = Proto("melsoft.resp.username_login","Mitsubishi Electric MELSOFT Protocol - " .. magic_bytes[0xd700] .. " - Username Login")

resp_username_login_protofields =
{
    username_token = ProtoField.bytes("melsoft.resp.username_login.username_token", "Username Token"),
    payload = ProtoField.bytes("melsoft.resp.username_login.payload", "Payload")
}

proto_melsoft_resp_username_login.fields = resp_username_login_protofields

resp_username_login_experts =
{
    username_login_correct_response = ProtoExpert.new("melsoft.resp.username_login.username_login_correct_response.expert", "Username Login response (correct username) - May be legitimate or an attempt to exploit CVE-2021-20594", expert.group.SECURITY, expert.severity.NOTE),
    username_login_wrong_response = ProtoExpert.new("melsoft.resp.username_login.username_login_wrong_response.expert", "Username Login response (wrong username) - May be an attempt to exploit CVE-2021-20594", expert.group.SECURITY, expert.severity.WARN)
}

proto_melsoft_resp_username_login.experts = resp_username_login_experts

function proto_melsoft_resp_username_login.dissector(buffer, pinfo, tree)
    local command_header_starting_byte = 0x15
    local status_value = buffer(command_header_starting_byte+4, 2):uint()
    local cmddata_starting_byte = 0x15+0x1a
    local cmddata_remaining_size_value = buffer(cmddata_starting_byte+4, 2):le_uint()
    local username_login_response = tree:add(proto_melsoft_resp_username_login, buffer(cmddata_starting_byte+6, cmddata_remaining_size_value), "Username Login Response")
    if status_value == 0 then
        username_login_response:add(resp_username_login_protofields["username_token"], buffer(cmddata_starting_byte+6, 0x10))
        username_login_response:add_proto_expert_info(resp_username_login_experts["username_login_correct_response"])
    else
        username_login_response:add(resp_username_login_protofields["payload"], buffer(cmddata_starting_byte+6, cmddata_remaining_size_value))
        username_login_response:add_proto_expert_info(resp_username_login_experts["username_login_wrong_response"])
    end
end

DissectorTable.get("melsoft.resp.resp_commands_table"):add(0x0131, proto_melsoft_resp_username_login)

-- Password login

proto_melsoft_req_password_login = Proto("melsoft.req.password_login","Mitsubishi Electric MELSOFT Protocol - " .. magic_bytes[0x5701] .. " - Password Login")

req_password_login_protofields =
{
    username_token = ProtoField.bytes("melsoft.req.password_login.username_token", "Username Token"),
    password = ProtoField.bytes("melsoft.req.password_login.password", "SHA256(Username Token + SHA256(Password))")
}

proto_melsoft_req_password_login.fields = req_password_login_protofields

req_password_login_experts =
{
    password_login_request = ProtoExpert.new("melsoft.req.password_login.password_login_request.expert", "Password Login request - May be legitimate or an attempt to exploit CVE-2021-20598", expert.group.SECURITY, expert.severity.NOTE)
}

proto_melsoft_req_password_login.experts = req_password_login_experts

function proto_melsoft_req_password_login.dissector(buffer, pinfo, tree)
    local cmddata_starting_byte = 0x15+0x18
    local cmddata_remaining_size_value = buffer(cmddata_starting_byte+4, 2):le_uint()
    local password_login_request = tree:add(proto_melsoft_req_password_login, buffer(cmddata_starting_byte+6, cmddata_remaining_size_value), "Password Login Request")
    password_login_request:add(req_password_login_protofields["username_token"], buffer(cmddata_starting_byte+6, 0x10))
    password_login_request:add(req_password_login_protofields["password"], buffer(cmddata_starting_byte+0x16, 0x20))
    password_login_request:add_proto_expert_info(req_password_login_experts["password_login_request"])
end

DissectorTable.get("melsoft.req.req_commands_table"):add(0x0132, proto_melsoft_req_password_login)

proto_melsoft_resp_password_login = Proto("melsoft.resp.password_login","Mitsubishi Electric MELSOFT Protocol - " .. magic_bytes[0xd700] .. " - Password Login")

resp_password_login_protofields =
{
    password_token = ProtoField.bytes("melsoft.resp.password_login.password_token", "Password Token"),
    sessionid_prefix = ProtoField.uint16("melsoft.resp.password_login.sessionid_prefix", "SessionID Prefix", base.HEX),
    payload = ProtoField.bytes("melsoft.resp.password_login.payload", "Payload")
}

proto_melsoft_resp_password_login.fields = resp_password_login_protofields

resp_password_login_experts =
{
    password_login_correct_response = ProtoExpert.new("melsoft.resp.password_login.password_login_correct_response.expert", "Password Login response (correct password) - May be legitimate or an attempt to exploit CVE-2021-20598", expert.group.SECURITY, expert.severity.NOTE),
    password_login_wrong_response = ProtoExpert.new("melsoft.resp.password_login.password_login_wrong_response.expert", "Password Login response (wrong password) - May be an attempt to exploit CVE-2021-20598", expert.group.SECURITY, expert.severity.WARN),
    password_login_wrong_response_plc_locked = ProtoExpert.new("melsoft.resp.password_login.password_login_wrong_response_plc_locked.expert", "Password Login response (wrong password and PLC locked) - Likely an attempt to exploit CVE-2021-20598", expert.group.SECURITY, expert.severity.ERROR)
}

proto_melsoft_resp_password_login.experts = resp_password_login_experts

function proto_melsoft_resp_password_login.dissector(buffer, pinfo, tree)
    local command_header_starting_byte = 0x15
    local status_value = buffer(command_header_starting_byte+4, 2):uint()
    local cmddata_starting_byte = 0x15+0x1a
    local cmddata_remaining_size_value = buffer(cmddata_starting_byte+4, 2):le_uint()
    local password_login_response = tree:add(proto_melsoft_resp_password_login, buffer(cmddata_starting_byte+6, cmddata_remaining_size_value), "Password Login Response")
    if status_value == 0 then
        password_login_response:add(resp_password_login_protofields["password_token"], buffer(cmddata_starting_byte+6, 0x10))
        password_login_response:add_le(resp_password_login_protofields["sessionid_prefix"], buffer(cmddata_starting_byte+0x26, 2))
        password_login_response:add_proto_expert_info(resp_password_login_experts["password_login_correct_response"])
    elseif (status_value == 0x844 or status_value == 0x944 or status_value == 0xa44) then
        password_login_response:add(resp_password_login_protofields["payload"], buffer(cmddata_starting_byte+6, cmddata_remaining_size_value))
        password_login_response:add_proto_expert_info(resp_password_login_experts["password_login_wrong_response"])
    else
        password_login_response:add(resp_password_login_protofields["payload"], buffer(cmddata_starting_byte+6, cmddata_remaining_size_value))
        password_login_response:add_proto_expert_info(resp_password_login_experts["password_login_wrong_response_plc_locked"])
    end
end

DissectorTable.get("melsoft.resp.resp_commands_table"):add(0x0132, proto_melsoft_resp_password_login)

-- Read User Information from PLC B

proto_melsoft_req_read_user_information_from_plc_b = Proto("melsoft.req.read_user_information_from_plc_b","Mitsubishi Electric MELSOFT Protocol - " .. magic_bytes[0x5701] .. " - Read User Information from PLC B")

req_read_user_information_from_plc_b_protofields =
{
    payload = ProtoField.bytes("melsoft.req.read_user_information_from_plc_b.payload", "Payload"),
}

proto_melsoft_req_read_user_information_from_plc_b.fields = req_read_user_information_from_plc_b_protofields

req_read_user_information_from_plc_b_experts =
{
    read_user_information_from_plc_b_request = ProtoExpert.new("melsoft.req.read_user_information_from_plc_b.read_user_information_from_plc_b_request.expert", "Read User Information from PLC B request - May be legitimate or an attempt to exploit NN-2021-0019", expert.group.SECURITY, expert.severity.NOTE)
}

proto_melsoft_req_read_user_information_from_plc_b.experts = req_read_user_information_from_plc_b_experts

function proto_melsoft_req_read_user_information_from_plc_b.dissector(buffer, pinfo, tree)
    local cmddata_starting_byte = 0x15+0x18
    local cmddata_remaining_size_value = buffer(cmddata_starting_byte+4, 2):le_uint()
    local read_user_information_from_plc_b_request = tree:add(proto_melsoft_req_read_user_information_from_plc_b, buffer(cmddata_starting_byte+6, cmddata_remaining_size_value), "Read User Information from PLC B Request")
    read_user_information_from_plc_b_request:add(req_read_user_information_from_plc_b_protofields["payload"], buffer(cmddata_starting_byte+6, cmddata_remaining_size_value))
    read_user_information_from_plc_b_request:add_proto_expert_info(req_read_user_information_from_plc_b_experts["read_user_information_from_plc_b_request"])
end

DissectorTable.get("melsoft.req.req_commands_table"):add(0x0134, proto_melsoft_req_read_user_information_from_plc_b)

proto_melsoft_resp_read_user_information_from_plc_b = Proto("melsoft.resp.read_user_information_from_plc_b","Mitsubishi Electric MELSOFT Protocol - " .. magic_bytes[0xd700] .. " - Read User Information from PLC B")

resp_read_user_information_from_plc_b_protofields =
{
    username = ProtoField.string("melsoft.resp.read_user_information_from_plc_b.username", "Username", base.UNICODE),
    password = ProtoField.bytes("melsoft.resp.read_user_information_from_plc_b.password", "SHA256(Password)"),
    access_level = ProtoField.uint16("melsoft.resp.read_user_information_from_plc_b.access_level", "Access Level", base.HEX, access_levels),
    payload = ProtoField.bytes("melsoft.resp.read_user_information_from_plc_b.payload", "Payload")
}

proto_melsoft_resp_read_user_information_from_plc_b.fields = resp_read_user_information_from_plc_b_protofields

resp_read_user_information_from_plc_b_experts =
{
    read_user_information_from_plc_b_correct_response = ProtoExpert.new("melsoft.resp.read_user_information_from_plc_b.read_user_information_from_plc_b_correct_response.expert", "Read User Information from PLC B response - May be legitimate or an attempt to exploit NN-2021-0019", expert.group.SECURITY, expert.severity.NOTE)
}

proto_melsoft_resp_read_user_information_from_plc_b.experts = resp_read_user_information_from_plc_b_experts

function proto_melsoft_resp_read_user_information_from_plc_b.dissector(buffer, pinfo, tree)
    local command_header_starting_byte = 0x15
    local status_value = buffer(command_header_starting_byte+4, 2):uint()
    local cmddata_starting_byte = 0x15+0x1a
    local cmddata_remaining_size_value = buffer(cmddata_starting_byte+4, 2):le_uint()
    local read_user_information_from_plc_b_response = tree:add(proto_melsoft_resp_read_user_information_from_plc_b, buffer(cmddata_starting_byte+6, cmddata_remaining_size_value), "Read User Information from PLC B Response")
    if status_value == 0 then
        local i=0
        while i < cmddata_remaining_size_value-0x4A do
            read_user_information_from_plc_b_response:add(resp_read_user_information_from_plc_b_protofields["username"], buffer(cmddata_starting_byte+6+i, 0x28), buffer(cmddata_starting_byte+6+i, 0x28):le_ustring())
            read_user_information_from_plc_b_response:add(resp_read_user_information_from_plc_b_protofields["password"], buffer(cmddata_starting_byte+0x2E+i, 0x20))
            read_user_information_from_plc_b_response:add(resp_read_user_information_from_plc_b_protofields["access_level"], buffer(cmddata_starting_byte+0x4E+i, 2))
            i = i+0x4A
        end
        read_user_information_from_plc_b_response:add_proto_expert_info(resp_read_user_information_from_plc_b_experts["read_user_information_from_plc_b_correct_response"])
    else
        read_user_information_from_plc_b_response:add(resp_read_user_information_from_plc_b_protofields["payload"], buffer(cmddata_starting_byte+6, cmddata_remaining_size_value))
    end
end

DissectorTable.get("melsoft.resp.resp_commands_table"):add(0x0134, proto_melsoft_resp_read_user_information_from_plc_b)

-- User Information Registration

proto_melsoft_req_user_information_registration = Proto("melsoft.req.user_information_registration","Mitsubishi Electric MELSOFT Protocol - " .. magic_bytes[0x5701] .. " - User Information Registration")

req_user_information_registration_protofields =
{
    no_of_users = ProtoField.uint16("melsoft.req.user_information_registration.no_of_users", "Number of Users", base.DEC),
    username = ProtoField.string("melsoft.req.user_information_registration.username", "Username", base.UNICODE),
    password = ProtoField.bytes("melsoft.req.user_information_registration.password", "SHA256(Password)"),
    access_level = ProtoField.uint16("melsoft.req.user_information_registration.access_level", "Access Level", base.HEX, access_levels)
}

proto_melsoft_req_user_information_registration.fields = req_user_information_registration_protofields

req_user_information_registration_fields =
{
    no_of_users_field = Field.new("melsoft.req.user_information_registration.no_of_users")
}

req_user_information_registration_experts =
{
    user_information_registration_request = ProtoExpert.new("melsoft.req.user_information_registration.user_information_registration_request.expert", "User Information Registration request - May be abused to exploit CVE-2021-20597", expert.group.SECURITY, expert.severity.NOTE)
}

proto_melsoft_req_user_information_registration.experts = req_user_information_registration_experts

function proto_melsoft_req_user_information_registration.dissector(buffer, pinfo, tree)
    local cmddata_starting_byte = 0x15+0x18
    local cmddata_remaining_size_value = buffer(cmddata_starting_byte+4, 2):le_uint()
    local user_information_registration_request = tree:add(proto_melsoft_req_user_information_registration, buffer(cmddata_starting_byte+6, cmddata_remaining_size_value), "User Information Registration Request")
    user_information_registration_request:add_le(req_user_information_registration_protofields["no_of_users"], buffer(cmddata_starting_byte+8, 2))
    local no_of_users_value = req_user_information_registration_fields["no_of_users_field"]()()
    for i=0,no_of_users_value-1
    do
        user_information_registration_request:add(req_user_information_registration_protofields["username"], buffer(cmddata_starting_byte+0xA+i*0x4A, 0x28), buffer(cmddata_starting_byte+0xA+i*0x4A, 0x28):le_ustring())
        user_information_registration_request:add(req_user_information_registration_protofields["password"], buffer(cmddata_starting_byte+0x32+i*0x4A, 0x20))
        user_information_registration_request:add(req_user_information_registration_protofields["access_level"], buffer(cmddata_starting_byte+0x52+i*0x4A, 2))
    end
    user_information_registration_request:add_proto_expert_info(req_user_information_registration_experts["user_information_registration_request"])
end

DissectorTable.get("melsoft.req.req_commands_table"):add(0x1133, proto_melsoft_req_user_information_registration)

proto_melsoft_resp_user_information_registration = Proto("melsoft.resp.user_information_registration","Mitsubishi Electric MELSOFT Protocol - " .. magic_bytes[0xd700] .. " - User Information Registration")

resp_user_information_registration_protofields =
{
    payload = ProtoField.bytes("melsoft.resp.user_information_registration.payload", "Payload")
}

proto_melsoft_resp_user_information_registration.fields = resp_user_information_registration_protofields

function proto_melsoft_resp_user_information_registration.dissector(buffer, pinfo, tree)
    local command_header_starting_byte = 0x15
    local status_value = buffer(command_header_starting_byte+4, 2):uint()
    local cmddata_starting_byte = 0x15+0x1a
    local cmddata_remaining_size_value = buffer(cmddata_starting_byte+4, 2):le_uint()
    local user_information_registration_response = tree:add(proto_melsoft_resp_user_information_registration, buffer(cmddata_starting_byte+6, cmddata_remaining_size_value), "User Information Registration Response")
    user_information_registration_response:add(resp_user_information_registration_protofields["payload"], buffer(cmddata_starting_byte+6, cmddata_remaining_size_value))
end

DissectorTable.get("melsoft.resp.resp_commands_table"):add(0x1133, proto_melsoft_resp_user_information_registration)