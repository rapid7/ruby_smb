module RubySMB
  module Dcerpc
    module Samr

      # [2.2.7.1 PSAMPR_SERVER_NAME](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-samr/7a77f1ce-cc55-4e36-a3c2-87c48f835f86)
      class PsamprServerName < RubySMB::Field::Stringz16
        default_parameters referent_byte_align: 2
        extend Ndr::PointerClassPlugin
      end

      # [3.1.5.1.4 SamrConnect (Opnum 0)](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-samr/defe2091-0a61-4dfa-be9a-2c1206d53a1f)
      class SamrConnectRequest < BinData::Record
        attr_reader :opnum

        endian :little

        psampr_server_name :server_name
        # Access control on a server object: bitwise OR of common ACCESS_MASK
        # and server ACCESS_MASK values (see lib/ruby_smb/dcerpc/samr.rb)
        ndr_uint32         :desired_access

        def initialize_instance
          super
          @opnum = SAMR_CONNECT
        end
      end

    end
  end
end


