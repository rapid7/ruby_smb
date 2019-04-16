module RubySMB
  module Dcerpc
    module Srvsvc

      UUID = '4b324fc8-1670-01d3-1278-5a47bf6ee188'
      VER_MAJOR = 3
      VER_MINOR = 0

      # Operation numbers
      NET_SHARE_ENUM_ALL = 0xF

      require 'ruby_smb/dcerpc/srvsvc/net_share_enum_all'

      def net_share_enum_all(host)
        bind(endpoint: RubySMB::Dcerpc::Srvsvc)

        net_share_enum_all_request_packet = RubySMB::Dcerpc::Srvsvc::NetShareEnumAll.new(host: host)
        response = dcerpc_request(net_share_enum_all_request_packet)

        shares = RubySMB::Dcerpc::Srvsvc::NetShareEnumAll.parse_response(response.stub.to_binary_s)
        shares.map{|s|{name: s[0], type: s[1], comment: s[2]}}
      end
    end
  end
end
