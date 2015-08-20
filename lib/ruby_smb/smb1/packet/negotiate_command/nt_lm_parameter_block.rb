module RubySMB
  module SMB1
    module Packet
      module NegotiateCommand

        # Represents a SMB1 Negotiate nt lm response parameter block.
        # [2.2.4.52.2 Response](https://msdn.microsoft.com/en-us/library/ee441946.aspx)
        class NTLMParameterBlock < BinData::Record
          bit8      :words_count
          bit16     :dialect_index
          bit8      :security_mode,     :onlyif => :nt_lm_negotiation?
          bit16     :max_mpx_count,     :onlyif => :nt_lm_negotiation?
          bit16     :max_number_vcs,    :onlyif => :nt_lm_negotiation?
          bit32     :max_buffer_size,   :onlyif => :nt_lm_negotiation?
          bit32     :max_raw_size,      :onlyif => :nt_lm_negotiation?
          bit32     :session_key,       :onlyif => :nt_lm_negotiation?
          bit32     :capabilities,      :onlyif => :nt_lm_negotiation?
          bit64     :system_time,       :onlyif => :nt_lm_negotiation?
          bit16     :server_time_zone,  :onlyif => :nt_lm_negotiation?
          bit8      :challenge_length,  :onlyif => :nt_lm_negotiation?

          def nt_lm_negotiation?
            words_count > 1
          end
        end
      end
    end
  end
end