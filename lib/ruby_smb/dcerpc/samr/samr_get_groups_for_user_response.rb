module RubySMB
  module Dcerpc
    module Samr

      # [[2.2.7.12 GROUP_MEMBERSHIP](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-samr/dc0d27ac-5218-4709-9d1b-cab6f6d90b10)
      class GroupMembership < Ndr::NdrStruct
        default_parameter byte_align: 4

        ndr_uint32 :relative_id
        ndr_uint32 :attributes
      end

      class PgroupMembershipArray < Ndr::NdrConfArray
        default_parameter type: :group_membership
        extend Ndr::PointerClassPlugin
      end

      # [2.2.7.13 SAMPR_GET_GROUPS_BUFFER](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-samr/31879676-cc95-4cf1-8f75-c09ddcef8750)
      class SamprGetGroupsBuffer < Ndr::NdrStruct
        default_parameter byte_align: 4

        ndr_uint32              :membership_count, initial_value: -> { groups.size }
        pgroup_membership_array :groups
      end

      class PsamprGetGroupsBuffer < SamprGetGroupsBuffer
        extend Ndr::PointerClassPlugin
      end

      # [3.1.5.9.1 SamrGetGroupsForUser (Opnum 39)](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-samr/a4adbf20-040f-4416-a960-e5b7917fdae7)
      class SamrGetGroupsForUserResponse < BinData::Record
        attr_reader :opnum

        endian :little

        psampr_get_groups_buffer :groups
        ndr_uint32               :error_status

        def initialize_instance
          super
          @opnum = SAMR_GET_GROUPS_FOR_USER
        end
      end

    end
  end
end

