module RubySMB
  module Dcerpc
    module Lsarpc

      # This class represents a LsarOpenPolicy Request Packet as defined in
      # [3.1.4.4.2 LsarOpenPolicy (Opnum 6)](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-lsad/2a482ccf-1f89-4693-8594-855ff738ae8a)
      class LsarOpenPolicyRequest < BinData::Record
        attr_reader :opnum

        endian :little

        ndr_wide_string_ptr     :system_name
        lsapr_object_attributes :object_attributes
        ndr_uint32              :access_mask

        def initialize_instance
          super
          @opnum = LSAR_OPEN_POLICY
        end
      end

    end
  end
end
