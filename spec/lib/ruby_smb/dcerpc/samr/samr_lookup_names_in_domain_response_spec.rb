RSpec.describe RubySMB::Dcerpc::Samr::SamrLookupNamesInDomainResponse do
  subject(:packet) { described_class.new }

  it { is_expected.to respond_to :relative_ids }
  it { is_expected.to respond_to :use }
  it { is_expected.to respond_to :error_status }
  it { is_expected.to respond_to :opnum }

  it 'is little endian' do
    expect(described_class.fields.instance_variable_get(:@hints)[:endian]).to eq :little
  end

  it 'is a BinData::Record' do
    expect(packet).to be_a(BinData::Record)
  end

  describe '#relative_ids' do
    it 'is a SamprHandle structure' do
      expect(packet.relative_ids).to be_a RubySMB::Dcerpc::Samr::SamprUlongArray
    end
  end

  describe '#use' do
    it 'is a SamprHandle structure' do
      expect(packet.use).to be_a RubySMB::Dcerpc::Samr::SamprUlongArray
    end
  end

  describe '#error_status' do
    it 'is a NdrUint32 structure' do
      expect(packet.error_status).to be_a RubySMB::Dcerpc::Ndr::NdrUint32
    end
  end

  describe '#initialize_instance' do
    it 'sets #opnum to SAMR_LOOKUP_NAMES_IN_DOMAIN constant' do
      expect(packet.opnum).to eq(RubySMB::Dcerpc::Samr::SAMR_LOOKUP_NAMES_IN_DOMAIN)
    end
  end

  it 'reads itself' do
    new_packet = described_class.new({
      relative_ids: { element_count: 2, elements: [ 500, 501 ] },
      use: { element_count: 2, elements:  [ 1, 2 ] },
      error_status: 0x11223344
    })
    expected_output = {
      relative_ids: { element_count: 2, elements: [ 500, 501 ] },
      use: { element_count: 2, elements:  [ 1, 2 ] },
      error_status: 0x11223344
    }
    expect(packet.read(new_packet.to_binary_s)).to eq(expected_output)
  end
end
