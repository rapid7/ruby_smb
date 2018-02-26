module RubySMB
  module SMB2
    module Dcerpc

      def net_share_enum_all(host)
        bind(endpoint: RubySMB::Dcerpc::Srvsvc)

        response = request(RubySMB::Dcerpc::Srvsvc::NET_SHARE_ENUM_ALL, host: host)

        shares = RubySMB::Dcerpc::Srvsvc::NetShareEnumAll.parse_response(response.stub.to_binary_s)
        shares.map{|s|{name: s[0], type: s[1], comment: s[2]}}
      end

      def bind(options={})
        bind_req = RubySMB::Dcerpc::Bind.new(options)
        ioctl_response = ioctl_send_recv(bind_req, options)
        dcerpc_response = RubySMB::Dcerpc::BindAck.read(ioctl_response.output_data)
        res_list = dcerpc_response.p_result_list
        if res_list.n_results == 0 ||
           res_list.p_results[0].result != RubySMB::Dcerpc::BindAck::ACCEPTANCE
          raise RubySMB::Dcerpc::Error::BindError,
            "Bind Failed (Result: #{res_list.p_results[0].result}, Reason: #{res_list.p_results[0].reason})"
        end
        dcerpc_response
      end

      def request(opnum, options={})
        dcerpc_request = RubySMB::Dcerpc::Request.new({ :opnum => opnum }, options)
        ioctl_response = ioctl_send_recv(dcerpc_request, options)
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

