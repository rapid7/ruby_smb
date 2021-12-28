module RubySMB
  module Dcerpc
    module Samr

      # [3.1.5.13.5 SamrRidToSid (Opnum 65)](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-samr/00ff8192-a4f6-45ba-9f65-917e46b6a693)
      class SamrRidToSidRequest < BinData::Record
        attr_reader :opnum

        endian :little

        sampr_handle :object_handle
        ndr_uint32   :rid

        def initialize_instance
          super
          @opnum = SAMR_RID_TO_SID
        end
      end

    end
  end
end

