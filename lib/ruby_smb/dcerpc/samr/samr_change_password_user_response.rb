module RubySMB
  module Dcerpc
    module Samr

      # [3.1.5.10.1 SamrChangePasswordUser (Opnum 38)](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-samr/9699d8ca-e1a4-433c-a8c3-d7bebeb01476)
      class SamrChangePasswordUserResponse < BinData::Record
        attr_reader :opnum

        endian :little

        ndr_uint32 :error_status

        def initialize_instance
          super
          @opnum = SAMR_CHANGE_PASSWORD_USER
        end
      end

    end
  end
end
