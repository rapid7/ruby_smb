module RubySMB
  # DCERPC PDU's
  # http://pubs.opengroup.org/onlinepubs/9629399/
  module Dcerpc

    class PduHeader < BinData::Record
      endian :little

      #common fields
      uint8 :rpc_vers # 00:01 RPC version
      uint8 :rpc_vers_minor # 01:01 minor version
      uint8 :ptype # 02:01 request PDU
      uint8 :pfc_flags # 03:01 flags

      uint32 :packed_drep # 04:04 NDR data rep format label

      uint16 :frag_length # 08:02 total length of fragment
      uint16 :auth_length # 10:02 length of auth_value
      uint32 :call_id # 12:04 call identifier
    end

    require 'ruby_smb/dcerpc/uuid'
    require 'ruby_smb/dcerpc/ndr'
    require 'ruby_smb/dcerpc/request'
    require 'ruby_smb/dcerpc/response'
    require 'ruby_smb/dcerpc/handle'
    require 'ruby_smb/dcerpc/srvsvc'
    require 'ruby_smb/dcerpc/bind'
  end
end