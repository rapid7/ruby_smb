module RubySMB
  module Dcerpc
    module Samr

      # [3.1.5.6.4 SamrSetInformationUser2 (Opnum 58)](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-samr/99ee9f39-43e8-4bba-ac3a-82e0c0e0699e)
      class SamrSetInformationUser2Request < BinData::Record
        attr_reader :opnum

        endian :little

        sampr_handle           :user_handle
        ndr_uint16             :user_information_class, initial_value: -> { buffer.tag }
        sampr_user_info_buffer :buffer

        def initialize_instance
          super
          @opnum = SAMR_SET_INFORMATION_USER2
        end
      end

    end
  end
end
