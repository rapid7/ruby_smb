module RubySMB
  module Dcerpc
    module Lsarpc

      # This class represents a LsarOpenPolicy2 Request Packet as defined in
      # [3.1.4.4.1 LsarOpenPolicy2 (Opnum 44)](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-lsad/9456a963-7c21-4710-af77-d0a2f5a72d6b)
      class LsarOpenPolicy2Request < BinData::Record
        attr_reader :opnum

        endian :little

        ndr_wide_stringz_ptr    :system_name
        lsapr_object_attributes :object_attributes
        ndr_uint32              :access_mask

        def initialize_instance
          super
          @opnum = LSAR_OPEN_POLICY2
        end
      end

    end
  end
end
