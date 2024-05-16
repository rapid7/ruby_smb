module RubySMB
  module Dcerpc
    module Lsarpc

      # This class represents a LsarClose Request Packet as defined in
      # [3.1.4.9.4 LsarClose (Opnum 0)](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-lsad/99dd2d7a-b0fc-4c6d-837a-2b4d342383ae)
      class LsarCloseHandleRequest < BinData::Record
        attr_reader :opnum

        endian :little

        lsapr_handle :policy_handle

        def initialize_instance
          super
          @opnum = LSAR_CLOSE_HANDLE
        end
      end

    end
  end
end
