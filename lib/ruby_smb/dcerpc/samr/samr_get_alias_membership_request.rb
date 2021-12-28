module RubySMB
  module Dcerpc
    module Samr

      #[2.2.7.6 SAMPR_SID_INFORMATION](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-samr/0c138399-f663-4039-b4e7-b3c9f82bff65)
      class SamprSidInformation < Ndr::NdrStruct
        default_parameter byte_align: 4

        rpc_sid :sid_pointer
      end

      class PsamprSidInformation < SamprSidInformation
        extend Ndr::PointerClassPlugin
      end

      class PsamprSidInformationArray < Ndr::NdrConfArray
        default_parameter type: :psampr_sid_information
        extend Ndr::PointerClassPlugin
      end

      # [2.2.7.5 SAMPR_PSID_ARRAY](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-samr/1d40622e-52e4-4aaa-bc77-aa626089f116)
      class SamprPsidArray < Ndr::NdrStruct
        default_parameter byte_align: 4

        ndr_uint32                   :sid_count, initial_value: -> { sids.size }
        psampr_sid_information_array :sids
      end

      # [3.1.5.9.2 SamrGetAliasMembership (Opnum 16)](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-samr/03184045-2208-4c02-b38b-ef955d6dc3ef)
      class SamrGetAliasMembershipRequest < BinData::Record
        attr_reader :opnum

        endian :little

        sampr_handle     :domain_handle
        sampr_psid_array :sid_array

        def initialize_instance
          super
          @opnum = SAMR_GET_ALIAS_MEMBERSHIP
        end
      end

    end
  end
end


