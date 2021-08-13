module RubySMB
  module Dcerpc
    module Samr

      class PulongArray < Ndr::NdrConfArray
        default_parameter type: :ndr_uint32
        extend Ndr::PointerClassPlugin
      end

      # [2.2.7.4 SAMPR_ULONG_ARRAY](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-samr/2feb3806-4db2-45b7-90d2-86c8336a31ba)
      class PsamprUlongArray < Ndr::NdrStruct
        default_parameter byte_align: 4

        ndr_uint32   :elem_count, initial_value: -> { elements.size }
        pulong_array :elements
      end

      # [3.1.5.9.2 SamrGetAliasMembership (Opnum 16)](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-samr/03184045-2208-4c02-b38b-ef955d6dc3ef)
      class SamrGetAliasMembershipResponse < BinData::Record
        attr_reader :opnum

        endian :little

        psampr_ulong_array :membership
        ndr_uint32         :error_status

        def initialize_instance
          super
          @opnum = SAMR_GET_ALIAS_MEMBERSHIP
        end
      end

    end
  end
end



