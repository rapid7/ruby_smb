module RubySMB
  module Dcerpc
    module Samr

      # [3.1.5.1.9 SamrOpenUser (Opnum 34)](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-samr/0aee1c31-ec40-4633-bb56-0cf8429093c0)
      class SamrOpenUserResponse < BinData::Record
        attr_reader :opnum

        endian :little

        sampr_handle :user_handle
        ndr_uint32   :error_status

        def initialize_instance
          super
          @opnum = SAMR_OPEN_USER
        end
      end

    end
  end
end


