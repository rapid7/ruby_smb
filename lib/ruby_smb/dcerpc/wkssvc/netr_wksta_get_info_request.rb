module RubySMB
  module Dcerpc
    module Wkssvc

      # [2.2.2.1 WKSSVC_IDENTIFY_HANDLE](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-wkst/9ef94a11-0e5c-49d7-9ac7-68d6f03565de)
      class WkssvcIdentifyHandle < Ndr::NdrWideStringPtr; end

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

