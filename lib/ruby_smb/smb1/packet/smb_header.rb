module RubySMB
  module SMB1
    module Packet
      # Represents the Header of an SMB1 packet as defined in
      # [2.2.3.1 SMB Header Extensions](https://msdn.microsoft.com/en-us/library/cc246254.aspx)
      class SMBHeader < BinData::Record
        endian  :little

        # SMBHeader
        bit32   :protocol,                    :label => 'Protocol ID Field',          :value => RubySMB::SMB1::SMB_PROTOCOL_ID
        bit8    :command,                     :label => 'SMB Command ID'
        bit32   :nt_status,                   :label => 'NTStatus Code'
        bit1    :flags_reply,                 :label => 'Response Packet?'
        bit1    :flags_opbatch,               :label => 'Batch OpLock'
        bit1    :flags_oplock,                :label => 'Exclusive Oplock'
        bit1    :flags_canonicalized_paths,   :label => 'Canonicalized Pathnames'
        bit1    :flags_case_insensitive,      :label => 'Pathnames Case Insensitive'
        bit1    :flags_reserved,              :label => 'Flags Reserved',             :value => 0
        bit1    :flags_buf_avail,             :label => 'Receive Buffer Available',   :value => 0
        bit1    :flags_lock_and_read_ok,      :label => 'Lock&Read Supported'
        bit1    :flags2_unicode,              :label => 'Unicode Strings',            :value => 1
        bit1    :flags2_nt_status,            :label => 'NTStatus Errors',            :value => 1
        bit1    :flags2_paging_io,            :label => 'Read if Execute'
        bit1    :flags2_dfs,                  :label => 'Use DFS'
        bit1    :flags2_extended_security,    :label => 'Extended Security'
        bit1    :flags2_reparse_path,         :label => '@GMT Token Required'
        bit3    :flags2_reserved1,            :label => 'Reserved',                   :value => 0
        bit1    :flags2_is_long_name,         :label => 'Long Names Used'
        bit1    :flags2_reserved2,            :label => 'Reserved',                   :value => 0
        bit1    :flags2_signature_required,   :label => 'Security Signature Required'
        bit1    :flags2_compressed,           :label => 'Compressed'
        bit1    :flags2_security_signature,   :label => 'Security Signing'
        bit1    :flags2_eas,                  :label => 'Extended Attributes'
        bit1    :flags2_long_names,           :label => 'Long Names Allowed'
        bit16   :pid_high,                    :label => 'PID High Bytes'
        bit64   :security_features,           :label => 'Security Features'
        bit16   :reserved,                    :label => 'Reserved'
        bit16   :tid,                         :label => 'Tree ID'
        bit16   :pid_low,                     :label => 'PID Low Bytes'
        bit16   :uid,                         :label => 'User ID'
        bit16   :mid,                         :label => 'Multiplex ID'
      end
    end
  end
end
