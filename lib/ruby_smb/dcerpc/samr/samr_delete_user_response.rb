module RubySMB
  module Dcerpc
    module Samr

      # [3.1.5.7.3 SamrDeleteUser (Opnum 35)](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-samr/4643a579-56ec-4c66-a1ef-4ab78dd21d73)
      class SamrDeleteUserResponse < BinData::Record
        attr_reader :opnum

        endian :little

        sampr_handle :user_handle
        ndr_uint32   :error_status

        def initialize_instance
          super
          @opnum = SAMR_DELETE_USER
        end
      end

    end
  end
end
