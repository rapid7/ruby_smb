module RubySMB
  module SMB1
    module Dcerpc

      def net_share_enum_all(host)
        bind(endpoint: RubySMB::Dcerpc::Srvsvc)

        response = request(RubySMB::Dcerpc::Srvsvc::NET_SHARE_ENUM_ALL, host: host)

        shares = RubySMB::Dcerpc::Srvsvc::NetShareEnumAll.parse_response(response.stub.to_binary_s)
        shares.map{|s|{name: s[0], type: s[1], comment: s[2]}}
      end

      def bind(options={})
        bind_req = RubySMB::Dcerpc::Bind.new(options)
        write(data: bind_req.to_binary_s)
        @size = 1024
        dcerpc_raw_response = read()
        dcerpc_response = RubySMB::Dcerpc::BindAck.read(dcerpc_raw_response)
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
        request = RubySMB::SMB1::Packet::Trans::TransactNmpipeRequest.new(options)
        @tree.set_header_fields(request)
        request.set_fid(@fid)
        request.data_block.trans_data.write_data = dcerpc_request.to_binary_s

        trans_nmpipe_raw_response = @tree.client.send_recv(request)
        trans_nmpipe_response = RubySMB::SMB1::Packet::Trans::TransactNmpipeResponse.read(trans_nmpipe_raw_response)
        RubySMB::Dcerpc::Response.read(trans_nmpipe_response.data_block.trans_data.read_data)
      end

    end
  end
end

