RSpec.describe RubySMB::Dcerpc::SecTrailer do
  subject(:packet) { described_class.new }

  it { is_expected.to respond_to :auth_type }
  it { is_expected.to respond_to :auth_level }
  it { is_expected.to respond_to :auth_pad_length }
  it { is_expected.to respond_to :auth_reserved }
  it { is_expected.to respond_to :auth_context_id }

  it 'is little endian' do
    expect(described_class.fields.instance_variable_get(:@hints)[:endian]).to eq :little
  end

  it 'has :byte_align parameter set to the expected value' do
    expect(described_class.default_parameters[:byte_align]).to eq(1)
  end

  describe '#auth_type' do
    it 'is a NdrUint8' do
      expect(packet.auth_type).to be_a RubySMB::Dcerpc::Ndr::NdrUint8
    end
  end

  describe '#auth_level' do
    it 'is a NdrUint8' do
      expect(packet.auth_level).to be_a RubySMB::Dcerpc::Ndr::NdrUint8
    end
  end

  describe '#auth_pad_length' do
    it 'is a NdrUint8' do
      expect(packet.auth_pad_length).to be_a RubySMB::Dcerpc::Ndr::NdrUint8
    end

    it 'defaults to 0' do
      expect(packet.auth_pad_length).to eq(0)
    end

    context 'when the parent structure does not have an #auth_pad field' do
      let(:pad) { 'A' * rand(0xFF) }
      let(:packet_with_parent) do
        Class.new(BinData::Record) do
          string      :other
          sec_trailer :sec_trailer
        end.new(other: pad)
      end

      it 'defaults to 0' do
        expect(packet_with_parent.sec_trailer.auth_pad_length).to eq(0)
      end
    end
  end

  describe '#auth_reserved' do
    it 'is a NdrUint8' do
      expect(packet.auth_reserved).to be_a RubySMB::Dcerpc::Ndr::NdrUint8
    end
  end

  describe '#auth_context_id' do
    it 'is a NdrUint32' do
      expect(packet.auth_context_id).to be_a RubySMB::Dcerpc::Ndr::NdrUint32
    end
  end

  it 'reads its own binary representation and output the same packet' do
    packet = described_class.new(
      auth_type: rand(0xFF),
      auth_level: rand(0xFF),
      auth_pad_length: rand(0xFF),
      auth_reserved: rand(0xFF),
      auth_context_id: rand(0xFF)
    )
    binary = packet.to_binary_s
    expect(described_class.read(binary)).to eq(packet)
  end

end
