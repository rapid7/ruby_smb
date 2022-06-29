module RubySMB
  module Dcerpc
    module Samr

      # [3.1.5.2.1 SamrEnumerateDomainsInSamServer (Opnum 6)](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-samr/2142fd2d-0854-42c1-a9fb-2fe964e381ce)
      class SamrEnumerateDomainsInSamServerRequest < BinData::Record
        attr_reader :opnum

        endian :little

        sampr_handle :server_handle
        ndr_uint32   :enumeration_context
        ndr_uint32   :prefered_maximum_length

        def initialize_instance
          super
          @opnum = SAMR_ENUMERATE_DOMAINS_IN_SAM_SERVER
        end
      end

    end
  end
end


