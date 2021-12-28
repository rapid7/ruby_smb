module RubySMB
  module Dcerpc
    module Samr

      # [3.1.5.1.5 SamrOpenDomain (Opnum 7)](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-samr/ba710c90-5b12-42f8-9e5a-d4aacc1329fa)
      class SamrOpenDomainRequest < BinData::Record
        attr_reader :opnum

        endian :little

        sampr_handle :server_handle
        # Access control on a server object: bitwise OR of common ACCESS_MASK
        # and domain ACCESS_MASK values (see lib/ruby_smb/dcerpc/samr.rb)
        ndr_uint32   :desired_access
        rpc_sid      :domain_id

        def initialize_instance
          super
          @opnum = SAMR_OPEN_DOMAIN
        end
      end

    end
  end
end


