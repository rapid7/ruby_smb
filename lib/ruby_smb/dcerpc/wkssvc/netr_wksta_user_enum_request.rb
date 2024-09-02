module RubySMB
  module Dcerpc
    module Wkssvc

      # [3.2.4.3 NetrWkstaUserEnum (Opnum 2)](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-wkst/4af41d6f-b800-4de1-af5b-0b15a85f8e04)
      class NetrWkstaUserEnumRequest < BinData::Record
        attr_reader :opnum

        endian :little

        wkssvc_identify_handle       :server_name
        lpwkssvc_user_enum_structure :user_info
        ndr_uint32                   :preferred_max_length, initial_value: 0xFFFFFFFF
        ndr_uint32_ptr               :result_handle, initial_value: 0

        def initialize_instance
          super
          @opnum = NETR_WKSTA_USER_ENUM
        end
      end

    end
  end
end

