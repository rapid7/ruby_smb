require 'net/ntlm'

module Custom
  module NTLM

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

Net::NTLM::EncodeUtil.send(:prepend, Custom::NTLM)
