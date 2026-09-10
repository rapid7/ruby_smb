require 'ruby_smb/nbss/name_service_opcode'
require 'ruby_smb/nbss/name_service_header_flags'
require 'ruby_smb/nbss/name_service_result_code'

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
      # RFC 1002 4.2.17: a node status query always asks for the wildcard name,
      # 16 bytes of 0x2A ('*') padded with 0x00.
      WILDCARD_NAME = '*'.ljust(16, "\x00").freeze

      endian :big

      # 12-byte NBNS header (RFC 1002 4.2.1.1 and 4.2.1.2).
      uint16                    :transaction_id, label: 'Transaction ID'
      name_service_opcode       :opcode,         label: 'Opcode'
      name_service_header_flags :nm_flags,       label: 'Flags'
      name_service_result_code  :rcode,          label: 'Result Code'
      uint16                    :qdcount,        label: 'QDCount', initial_value: 1
      uint16                    :ancount,        label: 'ANCount', initial_value: 0
      uint16                    :nscount,        label: 'NSCount', initial_value: 0
      uint16                    :arcount,        label: 'ARCount', initial_value: 0

      # Question section. For a node status query this is always the wildcard
      # NetBIOS name, L1-encoded.
      netbios_name :question_name,  label: 'Question Name', initial_value: WILDCARD_NAME
      uint16       :question_type,  label: 'Question Type',  initial_value: QUESTION_TYPE_NBSTAT
      uint16       :question_class, label: 'Question Class', initial_value: QUESTION_CLASS_IN
    end
  end
end
