module RubySMB
  module Dcerpc
    module Lsarpc

      # This class represents a LsarLookupSids Request Packet as defined in
      # [3.1.4.11 LsarLookupSids (Opnum 15)](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-lsat/eb7ac899-e697-4883-93de-1e60c7720c02)
      class LsarLookupSidsRequest < BinData::Record
        attr_reader :opnum

        endian :little

        lsapr_handle           :policy_handle
        lsapr_sid_enum_buffer  :sid_enum_buffer
        lsapr_translated_names :translated_names
        ndr_uint16             :lookup_level
        ndr_uint32             :mapped_count

        def initialize_instance
          super
          @opnum = LSAR_LOOKUP_SIDS
        end
      end

    end
  end
end
