RSpec.describe RubySMB::SMB2::Packet::TransformHeader do
  subject(:packet) { described_class.new }

  it { is_expected.to respond_to :protocol }
  it { is_expected.to respond_to :signature }
  it { is_expected.to respond_to :nonce }
  it { is_expected.to respond_to :original_message_size }
  it { is_expected.to respond_to :flags }
  it { is_expected.to respond_to :session_id }
  it { is_expected.to respond_to :encrypted_data }

  it 'is little endian' do
    expect(described_class.fields.instance_variable_get(:@hints)[:endian]).to eq :little
  end

  describe '#protocol' do
    it 'is a 32-bit field' do
      expect(packet.protocol).to be_a BinData::Bit32
    end

    it 'has an initial value of 0xFD534D42' do
      expect(packet.protocol).to eq(0xFD534D42)
    end
  end

  describe '#signature' do
    it 'is a String' do
      expect(packet.signature).to be_a BinData::String
    end
  end

  describe '#nonce' do
    it 'is a String' do
      expect(packet.nonce).to be_a BinData::String
    end
  end

  describe '#original_message_size  ' do
    it 'is a 32-bit unsigned integer' do
      expect(packet.original_message_size).to be_a BinData::Uint32le
    end
  end

  describe '#flags' do
    it 'is a 16-bit unsigned integer' do
      expect(packet.flags).to be_a BinData::Uint16le
    end
  end

  describe '#session_id' do
    it 'is a 64-bit unsigned integer' do
      expect(packet.session_id).to be_a BinData::Uint64le
    end
  end

  describe '#encrypted_data' do
    it 'is an Array' do
      expect(packet.encrypted_data).to be_a BinData::Array
    end
  end

  describe '#decrypt' do
    let(:key) { "\x56\x89\xd1\xbb\xf7\x45\xc0\xb6\x68\x81\x07\xe4\x7d\x35\xaf\xd3".b }
    let(:data) { 'data'.b }
    before :example do
      packet.original_message_size = data.length
    end

    it 'raises the expected exception if the given algorithm is invalid' do
      expect { packet.decrypt(key, algorithm: 'RC4') }.to raise_error(
        RubySMB::Error::EncryptionError,
        'Error while decrypting with \'RC4\' (ArgumentError: Invalid algorithm, must be either AES-128-CCM or AES-128-GCM)'
      )
    end

    context 'with AES-128-GCM algorithm (default)' do
      before :example do
        begin
          OpenSSL::Cipher.new('AES-128-GCM')
        rescue
          skip(
            "This test cannot be run since the version of OpenSSL the ruby "\
            "OpenSSL extension was built with (#{OpenSSL::OPENSSL_VERSION}) "\
            "does not support AES-128-GCM cipher")
        end
        packet.encrypted_data = "\x06\x45\x16\x36".bytes
        packet.signature = "\x63\xb2\xf9\xe0\xb7\x43\xdb\xaf\x26\x8e\xd7\x42\xd3\xb2\xde\x0d"
        packet.nonce = "\xe1\xb0\xa7\x20\xd9\xd9\x69\x3c\x79\xd0\x9c\x53\x00\x00\x00\x00"
      end

      it 'generates a cipher using OpenSSL::Cipher' do
        expect(OpenSSL::Cipher).to receive(:new).with('AES-128-GCM').and_call_original
        packet.decrypt(key)
      end

      it 'returns the expected decrypted string' do
        expect(packet.decrypt(key)).to eq(data)
      end

      it 'raises the expected exception if an error occurs' do
        allow(OpenSSL::Cipher).to receive(:new).and_raise(
          RuntimeError.new('unsupported cipher algorithm (AES-128-GCM)'))
        expect { packet.decrypt(key) }.to raise_error(
          RubySMB::Error::EncryptionError,
          'Error while decrypting with \'AES-128-GCM\' (RuntimeError: unsupported cipher algorithm (AES-128-GCM))'
        )
      end
    end

    context 'with AES-128-CCM algorithm' do
      before :example do
        packet.encrypted_data = "\xf0\x05\x61\x91".bytes
        packet.signature = "\xdd\x51\x9a\xc5\x6d\x38\x68\xdc\x36\x89\xb8\x99\xd8\x4a\xb8\x4a".b
        packet.nonce = "\x8a\x6e\x2a\x87\x11\x61\x85\xd2\x15\x69\xf7\x00\x00\x00\x00\x00".b
      end

      it 'generates a cipher using OpenSSL::CCM' do
        expect(OpenSSL::CCM).to receive(:new).with('AES', key, 16).and_call_original
        packet.decrypt(key, algorithm: 'AES-128-CCM')
      end

      it 'returns the expected decrypted string' do
        expect(packet.decrypt(key, algorithm: 'AES-128-CCM')).to eq(data)
      end

      it 'raises the expected exception if an error occurs' do
        allow(OpenSSL::CCM).to receive(:new).and_raise(
          OpenSSL::CCMError.new('unsupported cipher algorithm (AES-128-CCM)'))
        expect { packet.decrypt(key, algorithm: 'AES-128-CCM') }.to raise_error(
          RubySMB::Error::EncryptionError,
          'Error while decrypting with \'AES-128-CCM\' (OpenSSL::CCMError: unsupported cipher algorithm (AES-128-CCM))'
        )
      end
    end
  end

  describe '#encrypt' do
    let(:key)    { "\x56\x89\xd1\xbb\xf7\x45\xc0\xb6\x68\x81\x07\xe4\x7d\x35\xaf\xd3".b }
    let(:struct) { RubySMB::SMB2::Packet::TreeConnectRequest.new }

    it 'raises the expected exception if the given algorithm is invalid' do
      expect { packet.encrypt(struct, key, algorithm: 'RC4') }.to raise_error(
        RubySMB::Error::EncryptionError,
        'Error while encrypting with \'RC4\' (ArgumentError: Invalid algorithm, must be either AES-128-CCM or AES-128-GCM)'
      )
    end

    context 'with AES-128-GCM algorithm (default)' do
      before :example do
        begin
          OpenSSL::Cipher.new('AES-128-GCM')
        rescue
          skip(
            "This test cannot be run since the version of OpenSSL the ruby "\
            "OpenSSL extension was built with (#{OpenSSL::OPENSSL_VERSION}) "\
            "does not support AES-128-GCM cipher")
        end
      end

      it 'generates a cipher using OpenSSL::Cipher' do
        expect(OpenSSL::Cipher).to receive(:new).with('AES-128-GCM').and_call_original
        packet.encrypt(struct, key)
      end

      it 'encrypts a BinData structure' do
        packet.encrypt(struct, key)
        expect(packet.decrypt(key)).to eq(struct.to_binary_s)
      end

      it 'encrypts a string' do
        packet.encrypt('data', key)
        expect(packet.decrypt(key)).to eq('data')
      end

      it 'raises the expected exception if an error occurs' do
        allow(OpenSSL::Cipher).to receive(:new).and_raise(
          RuntimeError.new('unsupported cipher algorithm (AES-128-GCM)'))
        expect { packet.encrypt('data', key) }.to raise_error(
          RubySMB::Error::EncryptionError,
          'Error while encrypting with \'AES-128-GCM\' (RuntimeError: unsupported cipher algorithm (AES-128-GCM))'
        )
      end
    end

    context 'with AES-128-CCM algorithm' do
      it 'generates a cipher using OpenSSL::CCM' do
        expect(OpenSSL::CCM).to receive(:new).with('AES', key, 16).and_call_original
        packet.encrypt(struct, key, algorithm: 'AES-128-CCM')
      end

      it 'encrypts a BinData structure' do
        packet.encrypt(struct, key, algorithm: 'AES-128-CCM')
        expect(packet.decrypt(key, algorithm: 'AES-128-CCM')).to eq(struct.to_binary_s)
      end

      it 'encrypts a string' do
        packet.encrypt('data', key, algorithm: 'AES-128-CCM')
        expect(packet.decrypt(key, algorithm: 'AES-128-CCM')).to eq('data')
      end

      it 'raises the expected exception if an error occurs' do
        allow(OpenSSL::CCM).to receive(:new).and_raise(
          OpenSSL::CCMError.new('unsupported cipher algorithm (AES-128-CCM)'))
        expect { packet.encrypt('data', key, algorithm: 'AES-128-CCM') }.to raise_error(
          RubySMB::Error::EncryptionError,
          'Error while encrypting with \'AES-128-CCM\' (OpenSSL::CCMError: unsupported cipher algorithm (AES-128-CCM))'
        )
      end
    end
  end

  it 'reads binary data as expected' do
    data = described_class.new
    key = "\x56\x89\xd1\xbb\xf7\x45\xc0\xb6\x68\x81\x07\xe4\x7d\x35\xaf\xd3".b
    struct = RubySMB::SMB2::Packet::TreeConnectRequest.new
    data.encrypt(struct, key, algorithm: 'AES-128-CCM')
    expect(described_class.read(data.to_binary_s)).to eq(data)
  end
end

