module RubySMB
  module Dcerpc
    module Samr

      # [3.1.5.1.7 SamrOpenGroup (Opnum 19)](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-samr/d396e6c9-d04a-4729-b0d8-f50f2748f3c8)
      class SamrOpenGroupRequest < BinData::Record
        attr_reader :opnum

        endian :little

        sampr_handle :domain_handle
        # Access control on a server object: bitwise OR of common ACCESS_MASK
        # and user ACCESS_MASK values (see lib/ruby_smb/dcerpc/samr.rb)
        ndr_uint32   :desired_access
        ndr_uint32   :group_id

        def initialize_instance
          super
          @opnum = SAMR_OPEN_GROUP
        end
      end

    end
  end
end

