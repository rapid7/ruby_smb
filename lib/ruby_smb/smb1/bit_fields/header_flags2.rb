module RubySMB
  module SMB1
    module BitFields
      # The Flags2 bit-field for an SMB1 Header as defined in
      # [2.2.3.1 SMB Header Extensions](https://msdn.microsoft.com/en-us/library/cc246254.aspx)
      class HeaderFlags2 < BinData::Record
        endian  :little
        bit1    :reserved1,            :label => 'Reserved',                   :value => 0
        bit1    :is_long_name,         :label => 'Long Names Used'
        bit1    :reserved2,            :label => 'Reserved',                   :value => 0
        bit1    :signature_required,   :label => 'Security Signature Required'
        bit1    :compressed,           :label => 'Compressed'
        bit1    :security_signature,   :label => 'Security Signing'
        bit1    :eas,                  :label => 'Extended Attributes'
        bit1    :long_names,           :label => 'Long Names Allowed',         :value => 1


        bit1    :unicode,              :label => 'Unicode Strings',            :value => 1
        bit1    :nt_status,            :label => 'NTStatus Errors',            :value => 1
        bit1    :paging_io,            :label => 'Read if Execute'
        bit1    :dfs,                  :label => 'Use DFS'
        bit1    :extended_security,    :label => 'Extended Security'
        bit1    :reparse_path,         :label => '@GMT Token Required'
        resume_byte_alignment
      end
    end
  end
end