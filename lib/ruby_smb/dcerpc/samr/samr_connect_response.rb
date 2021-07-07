module RubySMB
  module Dcerpc
    module Samr

      # [3.1.5.1.4 SamrConnect (Opnum 0)](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-samr/defe2091-0a61-4dfa-be9a-2c1206d53a1f)
      class SamrConnectResponse < BinData::Record
        attr_reader :opnum

        endian :little

        sampr_handle :server_handle
        ndr_uint32   :error_status

        def initialize_instance
          super
          @opnum = SAMR_CONNECT
        end
      end

    end
  end
end

