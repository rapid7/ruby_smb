module RubySMB
  module Dcerpc
    module Wkssvc

      # [3.2.4.1 NetrWkstaGetInfo (Opnum 0)](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-wkst/4af41d6f-b800-4de1-af5b-0b15a85f8e04)
      class NetrWkstaGetInfoRequest < BinData::Record
        attr_reader :opnum

        endian :little

        wkssvc_identify_handle :server_name
        ndr_uint32             :level

        def initialize_instance
          super
          @opnum = NETR_WKSTA_GET_INFO
        end
      end

    end
  end
end

