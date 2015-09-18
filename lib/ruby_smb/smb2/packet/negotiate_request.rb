module RubySMB
  module SMB2
    module Packet
      # An SMB2 NEGOTIATE Request packet as defined by
      # [2.2.3 SMB2 NEGOTIATE Request](https://msdn.microsoft.com/en-us/library/cc246543.aspx)
      class NegotiateRequest < RubySMB::GenericPacket
        endian              :little
        smb2_header         :smb2_header
        uint16              :structure_size,      :label => 'Structure Size',     :initial_value => 36
        uint16              :dialect_count,       :label => 'Dialect Count'
        smb2_security_mode  :security_mode
        uint16              :reserved1,           :label => 'Reserved',           :initial_value => 0
        smb2_capabilities   :capabilities
        string              :client_guid,         :label => 'Client GUID',        :length => 16
        file_time           :client_start_time,   :label => 'Client Start Time',  :initial_value => 0
        array               :dialects,            :label => 'Dialects',           :type => :uint16,       :read_until => :eof

        def initialize_instance
          super
          self.smb2_header.command = RubySMB::SMB2::Commands::NEGOTIATE
        end
      end
    end
  end
end