module RubySMB
  module Dcerpc
    module Srvsvc

      class SrvSvcHandle < Dcerpc::NdrLpStr; end

      class SrvSvcSyntax < BinData::Record
        endian :little
        uuid   :if_uuid, initial_value: '4b324fc8-1670-01d3-1278-5a47bf6ee188'
        uint16 :if_ver, initial_value: 3
        uint16 :if_ver_minor, initial_value: 0
      end

      require 'ruby_smb/dcerpc/srvsvc/net_share_enum_all'
    end
  end
end
