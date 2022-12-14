require 'net/ntlm'

module RubySMB
  module NTLM
    module Custom
      module StringEncoder

        def self.prepended(base)
          base.singleton_class.send(:prepend, ClassMethods)
        end

        module ClassMethods
          def encode_utf16le(str)
            str.dup.force_encoding('UTF-8').encode(Encoding::UTF_16LE, Encoding::UTF_8).force_encoding('ASCII-8BIT')
          end
        end
      end
    end
  end
end

Net::NTLM::EncodeUtil.send(:prepend, RubySMB::NTLM::Custom::StringEncoder)
