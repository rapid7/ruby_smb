require 'spec_helper'

RSpec.describe RubySMB::Crypto::KDF do
  describe '.counter_mode' do
    it 'generates the expected 128-bit key' do
      expected_key = "\x3c\x5e\x0a\x1b\x0a\xce\xa5\xb2\x64\x3f\xab\x78\xdc\x82\x31\x3b".b
      expect(described_class.counter_mode('ki', 'label', 'context')).to eq(expected_key)
    end

    it 'generates the expected 265-bit key' do
      expected_key =
        "\x33\x4d\xa9\x6d\x24\x7e\xcb\x14\xf6\x24\x00\x97\x26\x51\xd5\xb4"\
        "\x54\x5f\xda\x95\xf0\x5a\xcb\x25\x92\x57\xae\x71\x1c\x37\x20\x5b".b
      expect(described_class.counter_mode('ki', 'label', 'context', length: 256)).to eq(expected_key)
    end

    it 'raises the expected exception when an error occurs' do
      allow(OpenSSL::Digest).to receive(:new).and_raise(OpenSSL::OpenSSLError)
      expect { described_class.counter_mode('ki', 'label', 'context') }.to raise_error(
        RubySMB::Error::EncryptionError,
        "Crypto::KDF.counter_mode OpenSSL error: OpenSSL::OpenSSLError"
      )
    end
  end
end
