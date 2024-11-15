module RubySMB
  module Dcerpc
    module Samr

      # [3.1.5.8.3 SamrGetMembersInGroup (Opnum 25)](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-samr/3ed5030d-88a3-42ca-a6e0-8c12aa2fdfbd)
      class SamrGetMembersInGroupRequest < BinData::Record
        attr_reader :opnum

        endian :little

        sampr_handle :group_handle

        def initialize_instance
          super
          @opnum = SAMR_GET_MEMBERS_IN_GROUP
        end
      end

    end
  end
end


