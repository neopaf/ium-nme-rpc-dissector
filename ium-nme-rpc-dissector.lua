-- ium-nme-rpc-dissector.lua
-- Routines for HP IUM rpc exchange protocol packet disassembly
-- Author : Alexander Petrossian <paf@yandex.ru>
-- Copyright 2023

nme = Proto("nme","HP IUM NME");

local f = nme.fields
f.transtype = ProtoField.string("nme.transtype", "Type" ,  "Type of transaction")
f.reply_time = ProtoField.relative_time("nme.reply_time", "Reply time")

f.peer_new_in = ProtoField.framenum("nme.reply_in", "New in", base.NONE)
f.peer_reply_in = ProtoField.framenum("nme.reply_in", "Reply in", base.NONE)
f.copy_new_in = ProtoField.framenum("nme.copy_reply_in", "Copy of new in", base.NONE)
f.copy_reply_in = ProtoField.framenum("nme.copy_reply_in", "Copy of reply in", base.NONE)

--/*
-- * NME Header
-- */
f.header = ProtoField.bytes("nme.header", "Header", base.NONE, nil, 0x0)
f.hf_version = ProtoField.uint8("nme.version", "Version", base.DEC)

local ClassFlags = { [0] = 'Not set', [1] = 'Set'}
f.hf_class = ProtoField.uint8("nme.class", "Class          ", base.HEX, nil, 0x0, "Class")

f.classflag_request	= ProtoField.uint8("nme.class.request", "Request", base.DEC,
	ClassFlags, 0x80, "Is request")
f.classflag_duplicate	= ProtoField.uint8("nme.class.duplicate", "Duplicate", base.DEC,
	ClassFlags, 0x40, "Is duplicate")
f.classflag_error	= ProtoField.uint8("nme.class.error", "Error", base.DEC,
	ClassFlags, 0x20, "Is error")

f.hf_msgType = ProtoField.uint32("nme.msgtype", "Message type" , base.HEX, nil, 0x0)
f.hf_msgId = ProtoField.uint32("nme.msgid", "Message id" , base.HEX, nil, 0x0)
f.hf_uniqueId = ProtoField.uint32("nme.uniqueid", "Unique id" , base.HEX, nil, 0x0)

----/*
---- * NME Fics Data
---- */
--f.hf_nme_data = ProtoField.bytes("nme.data", "Data", base.NONE, nil, 0x0, "NME data")
--f.hf_nme_data_fics = ProtoField.string("nme.data.fics", "Fics", "NME data fics")
--f.hf_nme_data_fics_name = ProtoField.string("nme.data.fics.name", "Name", "Fics name")
--f.hf_nme_data_fics_flags = ProtoField.uint8("nme.data.fics.flags", "Flags", base.DEC, nil, 0x0 , "Fics flags")
--f.hf_nme_data_fics_eye = ProtoField.uint8("nme.data.fics.eye", "Eye", base.DEC, nil, 0x0, "Fics eye")
--f.hf_nme_data_fics_len = ProtoField.uint32("nme.data.fics.length", "Length", base.DEC, nil, 0x0, "Fics length")
--f.hf_nme_data_fics_data = ProtoField.string("nme.data.fics.data", "Data",  "Fics data")

-- cross-refs

--transnumb -> {new=framenums, reply=framenums, new_time=time}
transnumbs={}

function getTransInfo(transnumb)
	local transinfo = transnumbs[transnumb]
	if transinfo == nil then
		transinfo = {new={}, reply={}}
		transnumbs[transnumb] = transinfo
	end
	return transinfo
end

function seenNew(framenum, time, transnumb)
	local transinfo = getTransInfo(transnumb)
	transinfo.new[framenum] = 0
	transinfo.new_time = newinfo.time
end

function seenReply(framenum, transnumb)
	local transinfo = getTransInfo(transnumb)
	transinfo.reply[framenum] = 0
end

function addTransInfo(subtree, time, transtype, my_framenum, transinfo)
	if transinfo == nil or (next(transinfo.reply) == nil)
	then
		subtree:add_expert_info(PI_SEQUENCE, PI_ERROR, "No reply"..#transinfo.reply)
	end

	if transinfo ~= nil and transinfo.new_time and time then
		local s,nsfrac = math.modf(time - transinfo.new_time)
		local dnstime = NSTime(s, nsfrac*1e9)
		if transtype=="reply" then subtree:add(f.reply_time, dnstime):set_generated() end
	end

	for peer_framenum,dummy_value in pairs(transinfo.new) do
		if my_framenum ~= peer_framenum then subtree:add(transtype=="new" and f.copy_new_in or f.peer_new_in, peer_framenum) end
	end
	for peer_framenum,dummy_value in pairs(transinfo.reply) do
		if my_framenum ~= peer_framenum then subtree:add(transtype=="reply" and f.copy_reply_in or f.peer_reply_in, peer_framenum) end
	end
end

-- create a function to dissect it
function nme.dissector(buffer,pinfo,tree)
	local offset = pinfo.desegment_offset or 0
	local NME_HEADER_SIZE = 16

	if buffer:len() == 0 then return end

	while true do
		pinfo.cols.protocol = "NME"

		--Check minimal packet size = NME_HEADER_SIZE
		if ((offset + NME_HEADER_SIZE) >  buffer:len()) then
			tree:add_expert_info(PI_REASSEMBLE, PI_ERROR, string.format("Packet size is incorrect. Current size = %s. Required size = %s (NME/Data = %s / %s )", buffer:len() - offset, NME_HEADER_SIZE, NME_HEADER_SIZE, "???" ))

			pinfo.desegment_len = (offset + NME_HEADER_SIZE) - buffer:len() --DESEGMENT_ONE_MORE_SEGMENT
			return
		end

		local flags = buffer(offset + 4,1):uint()
		local datalength = buffer(offset + 1,3):uint()-16
		nme_size = datalength + NME_HEADER_SIZE
		local transnumb = buffer(offset + 12,4):uint()

		--Check full packet size = NME_HEADER_SIZE + NME.DataLength
		local isFullPacket = true
		if ((offset + nme_size) > buffer:len()) then
			isFullPacket = false;
		end

		local transtype = bit.band(flags, 0x80) > 0 and "new" or "reply"
		local actual_nme_size = NME_HEADER_SIZE
		if isFullPacket then
			actual_nme_size = nme_size
		end

		local subtree = tree:add(nme,buffer(offset, actual_nme_size ),"HP IUM NME" )
		if not pinfo.visited then
			if transtype == "reply" then
				seenReply(pinfo.number, transnumb)
			else -- new
				seenNew(pinfo.number, pinfo.abs_ts, transnumb)
			end
		end

		subtree:add(f.transtype, transtype):set_generated()
		addTransInfo(subtree, pinfo.abs_ts, transtype, pinfo.number, transnumbs[transnumb])

		local headersubtree = subtree:add(f.header, buffer(offset, NME_HEADER_SIZE),"Header")
		local isError = bit.band(flags, 0x20) > 0

		local packetinfo  = transtype .. (isError and ' ERROR' or '')
		headersubtree:set_text("Header: "..packetinfo)
		pinfo.cols.info = packetinfo

		headersubtree:add(f.hf_version, buffer(offset + 0,1))
		local classsubtree = headersubtree:add_le( f.hf_class, buffer(offset + 4,1))
		classsubtree:add( f.classflag_request , buffer(offset + 4,1))
		classsubtree:add( f.classflag_duplicate , buffer(offset + 4,1))
		local errorsubtree = classsubtree:add( f.classflag_error , buffer(offset + 4,1))
		if isError then
			errorsubtree:add_expert_info(PI_ERROR, PI_ERROR, "Packet class is ERROR")
		end

		headersubtree:add(f.hf_msgType, buffer(offset + 5,3))
		headersubtree:add(f.hf_msgId, buffer(offset + 8,4))
		headersubtree:add(f.hf_uniqueId, buffer(offset + 12,4))

		--Check full packet size = NME_HEADER_SIZE + NME.DataLength
		if not isFullPacket then
			pinfo.desegment_len = (offset + nme_size) - buffer:len() --DESEGMENT_ONE_MORE_SEGMENT
			return
		end

		--local items = 0
		--if datalength > 0 and ((offset + nme_size) <= buffer:len()) then
		--	local ficssubtree = subtree:add(f.hf_nme_data, buffer(offset + NME_HEADER_SIZE, datalength ))
		--	local start_fics_offset = 64
		--	local fics_offset = 0
		--
		--	local logLevel = ""
		--	local logMessage = ""
		--
		--	while fics_offset < datalength do
		--
		--		--first read name and value
		--		local first_step_offset = fics_offset
		--
		--		--Name
		--		local fics_name = string.format("%s", buffer(offset + start_fics_offset + first_step_offset, 10):string())
		--		first_step_offset = first_step_offset + 10
		--
		--		--flag + Eye
		--		first_step_offset = first_step_offset + 2
		--
		--		-- Size
		--		local valuesize = buffer(offset + start_fics_offset + first_step_offset, 4):le_uint()
		--		first_step_offset = first_step_offset + 4
		--
		--		-- Value
		--			--fix crashdump wireshark
		--			local truncated_size = valuesize
		--			local start_truncated_string = ""
		--			local end_truncated_string = ""
		--			if (valuesize > 150) then
		--				truncated_size = 150
		--				start_truncated_string = "[truncated] "
		--				end_truncated_string = "..."
		--			end
		--
		--		local full_fics_value = string.format("%s", buffer(offset + start_fics_offset + first_step_offset, valuesize):string()) -- format to remove null-terminators
		--		local truncated_fics_value = start_truncated_string .. string.format("%s", buffer(offset + start_fics_offset + first_step_offset, truncated_size):string()) .. end_truncated_string
		--		--second read create tree with name and value
		--		local fics_name_and_value = fics_name .. "=" .. truncated_fics_value
		--
		--		-- LOG MESSAGES
		--		if isLogTran then
		--			if fics_name == "LEVEL" then
		--				logLevel = full_fics_value
		--			end
		--			if fics_name == "TEXT" then
		--				logMessage = full_fics_value
		--				logMessage = logMessage:gsub('\n',' ')
		--				logMessage = logMessage:gsub('\r',' ')
		--			end
		--		end
		--
		--		--FICS
		--		local currentfics = ficssubtree:add(f.hf_nme_data_fics, fics_name_and_value)
		--
		--		--Name
		--		currentfics:add(f.hf_nme_data_fics_name, buffer(offset + start_fics_offset + fics_offset, 10))
		--		fics_offset = fics_offset + 10
		--
		--		--flag
		--		currentfics:add(f.hf_nme_data_fics_flags, buffer(offset + start_fics_offset + fics_offset, 1))
		--		fics_offset = fics_offset + 1
		--
		--		-- Eye
		--		currentfics:add(f.hf_nme_data_fics_eye, buffer(offset + start_fics_offset + fics_offset, 1))
		--		fics_offset = fics_offset + 1
		--
		--		-- Size
		--		currentfics:add_le(f.hf_nme_data_fics_len, buffer(offset + start_fics_offset + fics_offset, 4))
		--		fics_offset = fics_offset + 4
		--
		--		-- Value
		--		currentfics:add(f.hf_nme_data_fics_data, buffer(offset + start_fics_offset + fics_offset, valuesize))
		--		fics_offset = fics_offset + valuesize
		--
		--		currentfics:set_text(fics_name .. " = ".. truncated_fics_value)
		--		items = items + 1
		--
		--		full_fics_value = full_fics_value:gsub('\n','\\n')
		--		full_fics_value = full_fics_value:gsub('\r','\\r')
		--		menu_scripttext = menu_scripttext .. 'ficsOut.AddString0("' .. fics_name .. '", "' .. full_fics_value .. '");\n'
		--		menu_ficstext = menu_ficstext .. fics_name .. '=' .. full_fics_value .. '\n'
		--	end
		--	ficssubtree:set_text("Data: " .. items .. " items (" .. datalength .. " bytes)")
		--end
		offset = offset + nme_size

		if (offset == buffer:len()) then
			break
		end
	end
end

tcp_table = DissectorTable.get("tcp.port")
tcp_table:add(9990,nme)
tcp_table:add(9991,nme)
tcp_table:add(9992,nme)
tcp_table:add(9993,nme)
tcp_table:add(9994,nme)
tcp_table:add(9995,nme)
tcp_table:add(9996,nme)
tcp_table:add(9997,nme)
tcp_table:add(9998,nme)
tcp_table:add(9999,nme)
