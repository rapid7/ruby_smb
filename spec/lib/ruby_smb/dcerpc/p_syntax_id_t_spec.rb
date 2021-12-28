RSpec.describe RubySMB::Dcerpc::PSyntaxIdT do
  subject(:packet) { described_class.new }

  it { is_expected.to respond_to :if_uuid }
  it { is_expected.to respond_to :if_ver_major }
  it { is_expected.to respond_to :if_ver_minor }

  it 'is little endian' do
    expect(described_class.fields.instance_variable_get(:@hints)[:endian]).to eq :little
  end

  it 'has :byte_align parameter set to the expected value' do
    expect(described_class.default_parameters[:byte_align]).to eq(4)
  end

  describe '#if_uuid' do
    it 'is a Uuid' do
      expect(packet.if_uuid).to be_a RubySMB::Dcerpc::Uuid
    end
  end

  describe '#if_ver_major' do
    it 'should be a NdrUint16' do
      expect(packet.if_ver_major).to be_a RubySMB::Dcerpc::Ndr::NdrUint16
    end
  end

  describe '#if_ver_minor' do
    it 'should be a NdrUint16' do
      expect(packet.if_ver_minor).to be_a RubySMB::Dcerpc::Ndr::NdrUint16
    end
  end

  it 'reads its own binary representation and output the same packet' do
    packet = described_class.new(
      if_uuid: '22fd0d58-357a-472d-9d03-5f19e09b3a92',
      if_ver_major: rand(0xFF),
      if_ver_minor: rand(0xFF)
    )
    binary = packet.to_binary_s
    expect(described_class.read(binary)).to eq(packet)
  end

end

