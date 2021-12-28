module RubySMB
  module Dcerpc

    # [2.2.2.10 rpc_auth_3 PDU](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-rpce/a6b7b03c-4ac5-4c25-8c52-f2bec872ac97)
    class RpcAuth3 < BinData::Record
      PTYPE = PTypes::RPC_AUTH3

      endian :little

      # PDU Header
      pdu_header  :pdu_header
      uint32      :pad

      # Auth Verifier
      sec_trailer :sec_trailer, onlyif: -> { pdu_header.auth_length > 0 }
      string      :auth_value,
        onlyif: -> { pdu_header.auth_length > 0 },
        read_length: -> { pdu_header.auth_length }

      def initialize_instance
        super
        pdu_header.ptype = PTYPE
      end
    end
  end
end


