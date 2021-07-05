require 'ruby_smb/dcerpc/ndr'

module RubySMB
  module Dcerpc
    module Svcctl

      # [3.1.4.1 RCloseServiceHandle (Opnum 0)](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-scmr/a2a4e174-09fb-4e55-bad3-f77c4b13245c)
      class CloseServiceHandleResponse < BinData::Record
        attr_reader :opnum

        endian :little

        sc_rpc_handle :h_sc_object
        ndr_uint32    :error_status

        def initialize_instance
          super
          @opnum = CLOSE_SERVICE_HANDLE
        end
      end

    end
  end
end


