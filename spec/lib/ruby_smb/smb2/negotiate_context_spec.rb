RSpec.describe RubySMB::SMB2::PreauthIntegrityCapabilities do
  subject(:capability) { described_class.new }

  it { is_expected.to respond_to :hash_algorithm_count }
  it { is_expected.to respond_to :salt_length }
  it { is_expected.to respond_to :hash_algorithms }
  it { is_expected.to respond_to :salt }

  it 'is little endian' do
    expect(described_class.fields.instance_variable_get(:@hints)[:endian]).to eq :little
  end

  describe '#hash_algorithm_count' do
    it 'is a 16-bit unsigned integer' do
      expect(capability.hash_algorithm_count).to be_a BinData::Uint16le
    end

    it 'is set to the #hash_algorithms array size' do
      array = [1, 2, 3]
      capability.hash_algorithms = array
      expect(capability.hash_algorithm_count).to eq(array.size)
    end
  end

  describe '#salt_length' do
    it 'is a 16-bit unsigned integer' do
      expect(capability.salt_length).to be_a BinData::Uint16le
    end

    it 'is set to the #salt string size' do
      salt = 'my_random_salt'
      capability.salt = salt
      expect(capability.salt_length).to eq(salt.size)
    end
  end

  describe '#hash_algorithms' do
    it 'is a BinData Array' do
      expect(capability.hash_algorithms).to be_a BinData::Array
    end

    it 'has #hash_algorithm_count elements' do
      capability.hash_algorithm_count = 3
      expect(capability.hash_algorithms.size).to eq 3
    end
  end

  describe '#salt' do
    it 'is a string' do
      expect(capability.salt).to be_a BinData::String
    end

    it 'should read #salt_length bytes' do
      salt = 'my_random_salt'
      capability.salt_length = 5
      expect(capability.salt.read(salt)).to eq(salt[0,5])
    end
  end

  it 'reads binary data as expected' do
    data = described_class.new(
      hash_algorithms: [described_class::SHA_512],
      salt: 'test salt'
    )
    expect(described_class.read(data.to_binary_s)).to eq(data)
  end
end

RSpec.describe RubySMB::SMB2::EncryptionCapabilities do
  subject(:capability) { described_class.new }

  it { is_expected.to respond_to :cipher_count }
  it { is_expected.to respond_to :ciphers }

  it 'is little endian' do
    expect(described_class.fields.instance_variable_get(:@hints)[:endian]).to eq :little
  end

  describe '#cipher_count' do
    it 'is a 16-bit unsigned integer' do
      expect(capability.cipher_count).to be_a BinData::Uint16le
    end

    it 'is set to the #ciphers array size' do
      array = [1, 2, 3]
      capability.ciphers = array
      expect(capability.cipher_count).to eq(array.size)
    end
  end

  describe '#ciphers' do
    it 'is a BinData Array' do
      expect(capability.ciphers).to be_a BinData::Array
    end

    it 'has #cipher_count elements' do
      capability.cipher_count = 3
      expect(capability.ciphers.size).to eq 3
    end
  end

  it 'reads binary data as expected' do
    data = described_class.new(
      ciphers: [described_class::AES_128_CCM, described_class::AES_128_GCM]
    )
    expect(described_class.read(data.to_binary_s)).to eq(data)
  end
end

RSpec.describe RubySMB::SMB2::CompressionCapabilities do
  subject(:capability) { described_class.new }

  it { is_expected.to respond_to :compression_algorithm_count }
  it { is_expected.to respond_to :padding }
  it { is_expected.to respond_to :flags }
  it { is_expected.to respond_to :compression_algorithms }

  it 'is little endian' do
    expect(described_class.fields.instance_variable_get(:@hints)[:endian]).to eq :little
  end

  describe '#compression_algorithm_count' do
    it 'is a 16-bit unsigned integer' do
      expect(capability.compression_algorithm_count).to be_a BinData::Uint16le
    end

    it 'is set to the #compression_algorithms array size' do
      array = [1, 2, 3]
      capability.compression_algorithms = array
      expect(capability.compression_algorithm_count).to eq(array.size)
    end
  end

  describe '#padding' do
    it 'is a 16-bit unsigned integer' do
      expect(capability.padding).to be_a BinData::Uint16le
    end
  end

  describe '#flags' do
    it 'is a 32-bit unsigned integer' do
      expect(capability.flags).to be_a BinData::Uint32le
    end
  end

  describe '#compression_algorithms' do
    it 'is a BinData Array' do
      expect(capability.compression_algorithms).to be_a BinData::Array
    end

    it 'has #compression_algorithm_count elements' do
      capability.compression_algorithm_count = 3
      expect(capability.compression_algorithms.size).to eq 3
    end
  end

  it 'reads binary data as expected' do
    data = described_class.new(
      compression_algorithms: [described_class::LZNT1, described_class::LZ77]
    )
    expect(described_class.read(data.to_binary_s)).to eq(data)
  end
end

RSpec.describe RubySMB::SMB2::NetnameNegotiateContextId  do
  subject(:capability) { described_class.new }

  it { is_expected.to respond_to :net_name }

  it 'is little endian' do
    expect(described_class.fields.instance_variable_get(:@hints)[:endian]).to eq :little
  end

  describe '#net_name' do
    it 'is a unicode string' do
      expect(capability.net_name).to be_a RubySMB::Field::Stringz16
    end
  end

  it 'reads binary data as expected' do
    data = described_class.new(
      net_name: 'netname test'
    )
    expect(described_class.read(data.to_binary_s)).to eq(data)
  end
end

RSpec.describe RubySMB::SMB2::NegotiateContext do
  class FakePacket < BinData::Record
    endian  :little
    string :garbage
    negotiate_context :nc
  end

  let(:test_packet) do
    packet = FakePacket.new
    packet.nc.context_type = described_class::SMB2_PREAUTH_INTEGRITY_CAPABILITIES
    packet
  end
  subject(:negotiate_context) { described_class.new }

  it { is_expected.to respond_to :pad }
  it { is_expected.to respond_to :context_type }
  it { is_expected.to respond_to :data_length }
  it { is_expected.to respond_to :reserved }
  it { is_expected.to respond_to :data }

  it 'is little endian' do
    expect(described_class.fields.instance_variable_get(:@hints)[:endian]).to eq :little
  end

  describe '#pad' do
    it 'is a string' do
      expect(negotiate_context.pad).to be_a BinData::String
    end

    it 'should keep the #context_type 8-byte aligned' do
      test_packet.garbage = 'foo'
      expect(test_packet.nc.context_type.abs_offset % 8).to eq(0)
    end
  end

  describe '#context_type ' do
    it 'is a 16-bit unsigned integer' do
      expect(negotiate_context.context_type).to be_a BinData::Uint16le
    end
  end

  describe '#data_length' do
    it 'is a 16-bit unsigned integer' do
      expect(negotiate_context.data_length).to be_a BinData::Uint16le
    end

    it 'should give the #data field length in bytes' do
      expect(described_class.new(context_type: described_class::SMB2_ENCRYPTION_CAPABILITIES).data_length)
        .to eq(RubySMB::SMB2::EncryptionCapabilities.new.num_bytes)
    end
  end

  describe '#data' do
    it 'is a BinData choice field' do
      expect(negotiate_context.data).to be_a BinData::Choice
    end

    context 'with a SMB2_PREAUTH_INTEGRITY_CAPABILITIES context type' do
      it 'selects the PreauthIntegrityCapabilities structure' do
        expect(described_class.new(context_type: described_class::SMB2_PREAUTH_INTEGRITY_CAPABILITIES).data)
          .to eq(RubySMB::SMB2::PreauthIntegrityCapabilities.new)
      end
    end

    context 'with a SMB2_ENCRYPTION_CAPABILITIES context type' do
      it 'selects the PreauthIntegrityCapabilities structure' do
        expect(described_class.new(context_type: described_class::SMB2_ENCRYPTION_CAPABILITIES).data)
          .to eq(RubySMB::SMB2::EncryptionCapabilities.new)
      end
    end

    context 'with a SMB2_COMPRESSION_CAPABILITIES context type' do
      it 'selects the PreauthIntegrityCapabilities structure' do
        expect(described_class.new(context_type: described_class::SMB2_COMPRESSION_CAPABILITIES).data)
          .to eq(RubySMB::SMB2::CompressionCapabilities.new)
      end
    end

    context 'with a SMB2_NETNAME_NEGOTIATE_CONTEXT_ID context type' do
      it 'selects the PreauthIntegrityCapabilities structure' do
        expect(described_class.new(context_type: described_class::SMB2_NETNAME_NEGOTIATE_CONTEXT_ID).data)
          .to eq(RubySMB::SMB2::NetnameNegotiateContextId.new)
      end
    end
  end

  describe '#pad_length' do
    it 'returns 0 when #context_type is already 8-byte aligned' do
      expect(test_packet.nc.pad_length).to eq(0)
    end

    it 'returns 2 when #context_type is only 2-byte aligned' do
      test_packet.garbage = 'align' + 'A'
      expect(test_packet.nc.pad_length).to eq(2)
    end
  end

  context 'with a SMB2_PREAUTH_INTEGRITY_CAPABILITIES context type' do
    it 'reads binary data as expected' do
      data = described_class.new(
        context_type: described_class::SMB2_PREAUTH_INTEGRITY_CAPABILITIES
      )
      data.data.hash_algorithms << RubySMB::SMB2::PreauthIntegrityCapabilities::SHA_512
      data.data.salt = 'test salt'
      expect(described_class.read(data.to_binary_s)).to eq(data)
    end
  end

  context 'with a SMB2_ENCRYPTION_CAPABILITIES context type' do
    it 'reads binary data as expected' do
      data = described_class.new(
        context_type: described_class::SMB2_ENCRYPTION_CAPABILITIES
      )
      data.data.ciphers = [
        RubySMB::SMB2::EncryptionCapabilities::AES_128_CCM,
        RubySMB::SMB2::EncryptionCapabilities::AES_128_GCM
      ]
      expect(described_class.read(data.to_binary_s)).to eq(data)
    end
  end

  context 'with a SMB2_COMPRESSION_CAPABILITIES context type' do
    it 'reads binary data as expected' do
      data = described_class.new(
        context_type: described_class::SMB2_COMPRESSION_CAPABILITIES
      )
      data.data.compression_algorithms = [
        RubySMB::SMB2::CompressionCapabilities::LZNT1,
        RubySMB::SMB2::CompressionCapabilities::LZ77
      ]
      expect(described_class.read(data.to_binary_s)).to eq(data)
    end
  end

  context 'with a SMB2_NETNAME_NEGOTIATE_CONTEXT_ID context type' do
    it 'reads binary data as expected' do
      data = described_class.new(
        context_type: described_class::SMB2_NETNAME_NEGOTIATE_CONTEXT_ID
      )
      data.data.net_name = 'netname test'
      expect(described_class.read(data.to_binary_s)).to eq(data)
    end
  end
end

