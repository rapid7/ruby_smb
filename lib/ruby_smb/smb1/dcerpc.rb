module RubySMB
  module SMB1
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
        write(data: action.to_binary_s)
        @size = 1024
        dcerpc_response = read()
        # TODO: parse response and check if it is a Bind_ack (12) response message
      end

      def request(action, options={})
        request = RubySMB::SMB1::Packet::Trans::TransactNmpipeRequest.new(options)
        @tree.set_header_fields(request)
        request.set_fid(@fid)
        request.data_block.trans_data.write_data = action.to_binary_s

        trans_nmpipe_raw_response = @tree.client.send_recv(request)
        trans_nmpipe_response = RubySMB::SMB1::Packet::Trans::TransactNmpipeResponse.read(trans_nmpipe_raw_response)
        RubySMB::Dcerpc::Response.read(trans_nmpipe_response.data_block.trans_data.read_data)
      end

    end
  end
end

