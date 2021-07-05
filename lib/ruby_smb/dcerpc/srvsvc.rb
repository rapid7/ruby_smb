module RubySMB
  module Dcerpc
    module Srvsvc

      UUID = '4b324fc8-1670-01d3-1278-5a47bf6ee188'
      VER_MAJOR = 3
      VER_MINOR = 0

      # Operation numbers
      NET_SHARE_ENUM_ALL = 0xF

      # [2.2.2.4 Share Types](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-srvs/6069f8c0-c93f-43a0-a5b4-7ed447eb4b84)
      SHARE_TYPES = {
        0x00000000 => 'DISK',
        0x00000001 => 'PRINTER',
        0x00000002 => 'DEVICE',
        0x00000003 => 'IPC',
        0x02000000 => 'CLUSTER_FS',
        0x04000000 => 'CLUSTER_SOFS',
        0x08000000 => 'CLUSTER_DFS'
      }

      require 'ruby_smb/dcerpc/srvsvc/net_share_enum_all'

      def net_share_enum_all(host)
        host = "\\\\#{host}" unless host.start_with?('\\\\')
        bind(endpoint: RubySMB::Dcerpc::Srvsvc)

        net_share_enum_all_request_packet = RubySMB::Dcerpc::Srvsvc::NetShareEnumAllRequest.new(server_name: host)
        raw_response = dcerpc_request(net_share_enum_all_request_packet)

        response = RubySMB::Dcerpc::Srvsvc::NetShareEnumAllResponse.read(raw_response)
        response.info_struct.share_info.buffer.map do |share|
          type = [SHARE_TYPES[share.shi1_type & 0x0FFFFFFF]]
          type << 'SPECIAL' unless share.shi1_type & 0x80000000 == 0
          type << 'TEMPORARY' unless share.shi1_type & 0x40000000 == 0
          {
            name: share.shi1_netname.encode('UTF-8'),
            type: type.join('|'),
            comment: share.shi1_remark.encode('UTF-8')
          }
        end
      end
    end
  end
end
