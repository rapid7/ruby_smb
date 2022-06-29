module RubySMB
  module Dcerpc
    module Samr

      # [3.1.5.11.2 SamrLookupNamesInDomain (Opnum 17)](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-samr/d91271c6-7b2e-4194-9927-8fabfa429f90)
      class SamrLookupNamesInDomainResponse < BinData::Record
        attr_reader :opnum

        endian :little

        sampr_ulong_array  :relative_ids
        sampr_ulong_array  :use
        ndr_uint32         :error_status

        def initialize_instance
          super
          @opnum = SAMR_LOOKUP_NAMES_IN_DOMAIN
        end
      end

    end
  end
end
