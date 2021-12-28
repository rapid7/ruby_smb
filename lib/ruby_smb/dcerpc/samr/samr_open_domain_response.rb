module RubySMB
  module Dcerpc
    module Samr

      # [3.1.5.1.5 SamrOpenDomain (Opnum 7)](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-samr/ba710c90-5b12-42f8-9e5a-d4aacc1329fa)
      class SamrOpenDomainResponse < BinData::Record
        attr_reader :opnum

        endian :little

        sampr_handle :domain_handle
        ndr_uint32   :error_status

        def initialize_instance
          super
          @opnum = SAMR_OPEN_DOMAIN
        end
      end

    end
  end
end


