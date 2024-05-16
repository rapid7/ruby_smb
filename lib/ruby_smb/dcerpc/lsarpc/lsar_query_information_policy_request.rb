module RubySMB
  module Dcerpc
    module Lsarpc

      # This class represents a LsarQueryInformationPolicy Request Packet as defined in
      # [3.1.4.4.4 LsarQueryInformationPolicy (Opnum 7)](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-lsad/3564ba70-84ea-4f04-a9dc-dede9f96a8bf)
      class LsarQueryInformationPolicyRequest < BinData::Record
        attr_reader :opnum

        endian :little

        lsapr_handle :policy_handle
        ndr_uint32   :information_class

        def initialize_instance
          super
          @opnum = LSAR_QUERY_INFORMATION_POLICY
        end
      end

    end
  end
end
