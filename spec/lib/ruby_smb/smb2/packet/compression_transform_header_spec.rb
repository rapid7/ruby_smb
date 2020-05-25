RSpec.describe RubySMB::SMB2::Packet::CompressionTransformHeader do
  subject(:packet) { described_class.new }

  it { is_expected.to respond_to :protocol }
  it { is_expected.to respond_to :original_compressed_segment_size }
  it { is_expected.to respond_to :compression_algorithm }
  it { is_expected.to respond_to :flags }
  it { is_expected.to respond_to :offset }

  it 'is little endian' do
    expect(described_class.fields.instance_variable_get(:@hints)[:endian]).to eq :little
  end

  describe '#protocol' do
    it 'is a 32-bit field' do
      expect(packet.protocol).to be_a BinData::Bit32
    end

    it 'is initialized with the value 0xFC534D42' do
      expect(packet.protocol).to eq(0xFC534D42)
    end
  end

  describe '#original_compressed_segment_size ' do
    it 'is a 32-bit unsigned integer' do
      expect(packet.original_compressed_segment_size).to be_a BinData::Uint32le
    end
  end

  describe '#compression_algorithm ' do
    it 'is a 16-bit unsigned integer' do
      expect(packet.compression_algorithm).to be_a BinData::Uint16le
    end
  end

  describe '#flags ' do
    it 'is a 16-bit unsigned integer' do
      expect(packet.flags).to be_a BinData::Uint16le
    end
  end

  describe '#offset' do
    it 'is a 32-bit unsigned integer' do
      expect(packet.offset).to be_a BinData::Uint32le
    end
  end

  it 'reads a binary data as expected' do
    data = described_class.new
    expect(described_class.read(data.to_binary_s)).to eq(data)
  end
end

RSpec.describe RubySMB::SMB2::Packet::Smb2CompressionPayloadHeader do
  subject(:packet) { described_class.new }

  it { is_expected.to respond_to :algorithm_id }
  it { is_expected.to respond_to :payload_length }

  it 'is little endian' do
    expect(described_class.fields.instance_variable_get(:@hints)[:endian]).to eq :little
  end

  describe '#algorithm_id ' do
    it 'is a 16-bit unsigned integer' do
      expect(packet.algorithm_id).to be_a BinData::Uint16le
    end
  end

  describe '#payload_length' do
    it 'is a 32-bit unsigned integer' do
      expect(packet.payload_length).to be_a BinData::Uint32le
    end
  end

  it 'reads a binary data as expected' do
    data = described_class.new
    expect(described_class.read(data.to_binary_s)).to eq(data)
  end
end

RSpec.describe RubySMB::SMB2::Packet::Smb2CompressionPatternPayloadV1 do
  subject(:packet) { described_class.new }

  it { is_expected.to respond_to :pattern }
  it { is_expected.to respond_to :repetitions }

  it 'is little endian' do
    expect(described_class.fields.instance_variable_get(:@hints)[:endian]).to eq :little
  end

  describe '#pattern' do
    it 'is a 8-bit unsigned integer' do
      expect(packet.pattern).to be_a BinData::Uint8
    end
  end

  describe '#repetitions' do
    it 'is a 32-bit unsigned integer' do
      expect(packet.repetitions).to be_a BinData::Uint32le
    end
  end

  it 'reads a binary data as expected' do
    data = described_class.new
    expect(described_class.read(data.to_binary_s)).to eq(data)
  end
end
