module RubySMB
  module Dcerpc
    module Samr

      # [3.1.5.11.1 SamrLookupDomainInSamServer (Opnum 5)](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-samr/47492d59-e095-4398-b03e-8a062b989123)
      class SamrLookupDomainInSamServerResponse < BinData::Record
        attr_reader :opnum

        endian :little

        prpc_sid   :domain_id
        ndr_uint32 :error_status

        def initialize_instance
          super
          @opnum = SAMR_LOOKUP_DOMAIN_IN_SAM_SERVER
        end
      end

    end
  end
end



