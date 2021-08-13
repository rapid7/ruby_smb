module RubySMB
  module Dcerpc
    module Samr

      # [3.1.5.1.9 SamrOpenUser (Opnum 34)](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-samr/0aee1c31-ec40-4633-bb56-0cf8429093c0)
      class SamrOpenUserRequest < BinData::Record
        attr_reader :opnum

        endian :little

        sampr_handle :domain_handle
        # Access control on a server object: bitwise OR of common ACCESS_MASK
        # and user ACCESS_MASK values (see lib/ruby_smb/dcerpc/samr.rb)
        ndr_uint32   :desired_access
        ndr_uint32   :user_id

        def initialize_instance
          super
          @opnum = SAMR_OPEN_USER
        end
      end

    end
  end
end

