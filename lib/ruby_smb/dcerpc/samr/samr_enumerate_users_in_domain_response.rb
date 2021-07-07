module RubySMB
  module Dcerpc
    module Samr

      # [2.2.3.9 SAMPR_RID_ENUMERATION](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-samr/5c94a35a-e7f2-4675-af34-741f5a8ee1a2)
      class SamprRidEnumeration < Ndr::NdrStruct
        default_parameters byte_align: 4
        endian :little

        ndr_uint32         :relative_id
        rpc_unicode_string :name
      end

      class SamprRidEnumerationArray < Ndr::NdrConfArray
        default_parameter type: :sampr_rid_enumeration
      end

      class PsamprRidEnumerationArray < SamprRidEnumerationArray
        extend Ndr::PointerClassPlugin
      end

      # [2.2.3.10 SAMPR_ENUMERATION_BUFFER](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-samr/c53161a4-38e8-4a28-a33e-0d378fce03dd)
      class SamprEnumerationBuffer < Ndr::NdrStruct
        default_parameters byte_align: 4
        endian :little

        ndr_uint32                   :entries_read
        psampr_rid_enumeration_array :buffer
      end

      class PsamprEnumerationBuffer < SamprEnumerationBuffer
        extend Ndr::PointerClassPlugin
      end

      # [3.1.5.2.5 SamrEnumerateUsersInDomain (Opnum 13)](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-samr/6bdc92c0-c692-4ffb-9de7-65858b68da75)
      class SamrEnumerateUsersInDomainResponse < BinData::Record
        attr_reader :opnum

        endian :little

        ndr_uint32                :enumeration_context
        psampr_enumeration_buffer :buffer
        ndr_uint32                :count_returned
        ndr_uint32                :error_status

        def initialize_instance
          super
          @opnum = SAMR_ENUMERATE_USERS_IN_DOMAIN
        end
      end

    end
  end
end

