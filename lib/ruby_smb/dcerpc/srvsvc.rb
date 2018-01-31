module RubySMB
  module Dcerpc
    module Srvsvc

      class SrvSvcHandle < Dcerpc::NdrLpStr; end

      require 'ruby_smb/dcerpc/srvsvc/net_share_enum_all'
    end
  end
end
