module RubySMB
  module Nbss
    # NetBIOS Name Service (NBNS) Node Status Request packet, as defined in
    # [RFC 1002 4.2.17](https://tools.ietf.org/html/rfc1002#section-4.2.17).
    # Sent over UDP to port 137 to retrieve a host's NetBIOS name table.
    class NodeStatusRequest < BinData::Record
      # NBSTAT question type, RFC 1002 4.2.1.3.
      QUESTION_TYPE_NBSTAT = 0x0021
      # Internet class.
      QUESTION_CLASS_IN    = 0x0001

      endian :big

      # 12-byte NBNS header (RFC 1002 4.2.1.1 and 4.2.1.2).
      uint16 :transaction_id,  label: 'Transaction ID'
      uint16 :flags,           label: 'Flags',     initial_value: 0x0000
      uint16 :qdcount,         label: 'QDCount',   initial_value: 1
      uint16 :ancount,         label: 'ANCount',   initial_value: 0
      uint16 :nscount,         label: 'NSCount',   initial_value: 0
      uint16 :arcount,         label: 'ARCount',   initial_value: 0

      # Question section. For a node status query this is always the wildcard
      # NetBIOS name (16 bytes of 0x2A / 0x00), L1-encoded.
      netbios_name :question_name,  label: 'Question Name'
      uint16       :question_type,  label: 'Question Type',  initial_value: QUESTION_TYPE_NBSTAT
      uint16       :question_class, label: 'Question Class', initial_value: QUESTION_CLASS_IN
    end
  end
end
