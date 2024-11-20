module RubySMB
  module Dcerpc
    module Samr
      # [2.2.7.14 SAMPR_GET_MEMBERS_BUFFER](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-samr/225147b1-45b7-4fde-a5bf-bf420e18fa08)
      class SamprGetMembersBuffer < Ndr::NdrStruct
        default_parameter byte_align: 4

        ndr_uint32                 :member_count
        ndr_uint32_conf_array_ptr  :members,    type: :ndr_uint32
        ndr_uint32_conf_array_ptr  :attributes, type: :ndr_uint32
      end

      class PsamprGetMembersBuffer < SamprGetMembersBuffer
        extend Ndr::PointerClassPlugin
      end

      # [3.1.5.8.3 SamrGetMembersInGroup (Opnum 25)](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-samr/a4adbf20-040f-4416-a960-e5b7917fdae7)
      class SamrGetMembersInGroupResponse < BinData::Record
        attr_reader :opnum

        endian :little

        psampr_get_members_buffer  :members
        ndr_uint32                 :error_status

        def initialize_instance
          super
          @opnum = SAMR_GET_MEMBERS_IN_GROUP
        end
      end
    end
  end
end

