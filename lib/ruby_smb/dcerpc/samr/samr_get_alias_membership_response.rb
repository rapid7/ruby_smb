module RubySMB
  module Dcerpc
    module Samr

      # [3.1.5.9.2 SamrGetAliasMembership (Opnum 16)](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-samr/03184045-2208-4c02-b38b-ef955d6dc3ef)
      class SamrGetAliasMembershipResponse < BinData::Record
        attr_reader :opnum

        endian :little

        sampr_ulong_array  :membership
        ndr_uint32         :error_status

        def initialize_instance
          super
          @opnum = SAMR_GET_ALIAS_MEMBERSHIP
        end
      end

    end
  end
end



