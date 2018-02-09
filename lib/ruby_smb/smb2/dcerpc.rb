module RubySMB
  module SMB2
    module Dcerpc

      def net_share_enum_all(host)
        bind(RubySMB::Dcerpc::Bind.new(endpoint: RubySMB::Dcerpc::Srvsvc))

        request = RubySMB::Dcerpc::Request.new(
          opnum: RubySMB::Dcerpc::Srvsvc::NetShareEnumAll::Opnum,
          stub: RubySMB::Dcerpc::Srvsvc::NetShareEnumAll.new(host: "\\\\#{host}").to_binary_s
        )
        #request.call_id = 1
        response = request(request)

        shares = RubySMB::Dcerpc::Srvsvc::NetShareEnumAll.parse_response(response.stub.to_binary_s)
        shares.map{|s|{name: s[0], type: s[1], comment: s[2]}}
      end

      def bind(action, options={})
        ioctl_response = ioctl_send_recv(action, options)
        # TODO: parse response and check if it is a Bind_ack (12) response message
      end

      def request(action, options={})
        ioctl_response = ioctl_send_recv(action, options)
        RubySMB::Dcerpc::Response.read(ioctl_response.output_data)
      end

      def ioctl_send_recv(action, options={})
        request = set_header_fields(RubySMB::SMB2::Packet::IoctlRequest.new(options))
        request.ctl_code = 0x0011C017
        request.flags.is_fsctl = 0x00000001
        request.buffer = action.to_binary_s
        ioctl_raw_response = @tree.client.send_recv(request)
        RubySMB::SMB2::Packet::IoctlResponse.read(ioctl_raw_response)
      end

    end
  end
end

