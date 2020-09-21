module RubySMB
  module Dcerpc
    MAX_XMIT_FRAG = 4280
    MAX_RECV_FRAG = 4280

    require 'windows_error/win32'
    require 'ruby_smb/dcerpc/error'
    require 'ruby_smb/dcerpc/uuid'
    require 'ruby_smb/dcerpc/ndr'
    require 'ruby_smb/dcerpc/ptypes'
    require 'ruby_smb/dcerpc/p_syntax_id_t'
    require 'ruby_smb/dcerpc/rrp_unicode_string'
    require 'ruby_smb/dcerpc/rpc_security_attributes'
    require 'ruby_smb/dcerpc/pdu_header'
    require 'ruby_smb/dcerpc/srvsvc'
    require 'ruby_smb/dcerpc/svcctl'
    require 'ruby_smb/dcerpc/winreg'
    require 'ruby_smb/dcerpc/netlogon'
    require 'ruby_smb/dcerpc/request'
    require 'ruby_smb/dcerpc/response'
    require 'ruby_smb/dcerpc/bind'
    require 'ruby_smb/dcerpc/bind_ack'



    # Bind to the remote server interface endpoint.
    #
    # @param options [Hash] the options to pass to the Bind request packet. At least, :endpoint must but provided with an existing Dcerpc class
    # @return [RubySMB::Dcerpc::BindAck] the BindAck response packet
    # @raise [RubySMB::Dcerpc::Error::InvalidPacket] if an invalid packet is received
    # @raise [RubySMB::Dcerpc::Error::BindError] if the response is not a BindAck packet or if the Bind result code is not ACCEPTANCE
    def bind(options={})
      bind_req = RubySMB::Dcerpc::Bind.new(options)
      write(data: bind_req.to_binary_s)
      @size = 1024
      dcerpc_raw_response = read()
      begin
        dcerpc_response = RubySMB::Dcerpc::BindAck.read(dcerpc_raw_response)
      rescue IOError
        raise RubySMB::Dcerpc::Error::InvalidPacket, "Error reading the DCERPC response"
      end
      unless dcerpc_response.pdu_header.ptype == RubySMB::Dcerpc::PTypes::BIND_ACK
        raise RubySMB::Dcerpc::Error::BindError, "Not a BindAck packet"
      end

      res_list = dcerpc_response.p_result_list
      if res_list.n_results == 0 ||
         res_list.p_results[0].result != RubySMB::Dcerpc::BindAck::ACCEPTANCE
        raise RubySMB::Dcerpc::Error::BindError,
          "Bind Failed (Result: #{res_list.p_results[0].result}, Reason: #{res_list.p_results[0].reason})"
      end
      @tree.client.max_buffer_size = dcerpc_response.max_xmit_frag
      dcerpc_response
    end

  end
end
