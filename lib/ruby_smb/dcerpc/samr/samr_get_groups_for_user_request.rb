module RubySMB
  module Dcerpc
    module Samr

      # [3.1.5.9.1 SamrGetGroupsForUser (Opnum 39)](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-samr/a4adbf20-040f-4416-a960-e5b7917fdae7)
      class SamrGetGroupsForUserRequest < BinData::Record
        attr_reader :opnum

        endian :little

        sampr_handle :user_handle

        def initialize_instance
          super
          @opnum = SAMR_GET_GROUPS_FOR_USER
        end
      end

    end
  end
end


