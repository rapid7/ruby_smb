module RubySMB
  module Dcerpc
    module Wkssvc

      # [3.2.4.3 NetrWkstaUserEnum (Opnum 2)](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-wkst/4af41d6f-b800-4de1-af5b-0b15a85f8e04)
      class NetrWkstaUserEnumResponse < BinData::Record
        attr_reader :opnum

        endian :little

        lpwkssvc_user_enum_structure :user_info
        ndr_uint32_ptr               :total_entries
        ndr_uint32_ptr               :result_handle
        ndr_uint32                   :error_status

        def initialize_instance
          super
          @opnum = NETR_WKSTA_USER_ENUM
        end
      end

    end
  end
end

