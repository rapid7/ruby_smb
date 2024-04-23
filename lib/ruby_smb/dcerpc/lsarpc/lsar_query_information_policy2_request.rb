module RubySMB
  module Dcerpc
    module Lsarpc

      # This class represents a LsarQueryInformationPolicy2 Request Packet as defined in
      # [3.1.4.4.4 LsarQueryInformationPolicy2 (Opnum 46)](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-lsad/516f503c-0230-489d-b012-e650b46b66a2)
      class LsarQueryInformationPolicy2Request < BinData::Record
        attr_reader :opnum

        endian :little

        lsapr_handle :policy_handle
        ndr_uint32   :information_class

        def initialize_instance
          super
          @opnum = LSAR_QUERY_INFORMATION_POLICY2
        end
      end

    end
  end
end
