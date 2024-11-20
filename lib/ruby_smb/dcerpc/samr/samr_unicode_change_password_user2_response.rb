module RubySMB
  module Dcerpc
    module Samr

      # [3.1.5.10.3 SamrUnicodeChangePasswordUser2 (Opnum 55)](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-samr/acb3204a-da8b-478e-9139-1ea589edb880)
      class SamrUnicodeChangePasswordUser2Response < BinData::Record
        attr_reader :opnum

        endian :little

        ndr_uint32 :error_status

        def initialize_instance
          super
          @opnum = SAMR_UNICODE_CHANGE_PASSWORD_USER2
        end
      end

    end
  end
end
