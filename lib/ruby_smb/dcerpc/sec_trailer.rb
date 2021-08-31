module RubySMB
  module Dcerpc

    # [2.2.2.11 sec_trailer Structure](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-rpce/ab45c6a5-951a-4096-b805-7347674dc6ab)
    class SecTrailer < Ndr::NdrStruct
      # Disabling auto alignment since it is handled by the parent structure directly
      default_parameter byte_align: 1
      endian :little

      ndr_uint8  :auth_type
      ndr_uint8  :auth_level
      ndr_uint8  :auth_pad_length, initial_value: -> { get_auth_pad_length(@obj) }
      ndr_uint8  :auth_reserved
      ndr_uint32 :auth_context_id

      def get_auth_pad_length(obj)
        parent = obj&.parent&.parent
        if parent&.respond_to?(:auth_pad)
          return parent.auth_pad.length if parent.auth_pad.respond_to?(:length)
        end
        0
      end
    end

  end
end
