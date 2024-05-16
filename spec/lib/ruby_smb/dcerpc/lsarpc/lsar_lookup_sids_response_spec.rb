require 'ruby_smb/dcerpc/ndr'

RSpec.describe RubySMB::Dcerpc::Lsarpc::LsarLookupSidsResponse do
  subject(:packet) { described_class.new }

  it { is_expected.to respond_to :referenced_domains }
  it { is_expected.to respond_to :translated_names }
  it { is_expected.to respond_to :mapped_count }
  it { is_expected.to respond_to :error_status }
  it { is_expected.to respond_to :opnum }

  it 'is little endian' do
    expect(described_class.fields.instance_variable_get(:@hints)[:endian]).to eq :little
  end
  it 'is a BinData::Record' do
    expect(packet).to be_a(BinData::Record)
  end
  describe '#referenced_domains' do
    it 'is an LsaprReferencedDomainListPtr structure' do
      expect(packet.referenced_domains).to be_a RubySMB::Dcerpc::Lsarpc::LsaprReferencedDomainListPtr
    end
  end
  describe '#translated_names' do
    it 'is an LsaprTranslatedNames structure' do
      expect(packet.translated_names).to be_a RubySMB::Dcerpc::Lsarpc::LsaprTranslatedNames
    end
  end
  describe '#mapped_count' do
    it 'is an NdrUint32 structure' do
      expect(packet.mapped_count).to be_a RubySMB::Dcerpc::Ndr::NdrUint32
    end
  end
  describe '#error_status' do
    it 'is an NdrUint32' do
      expect(packet.error_status).to be_a RubySMB::Dcerpc::Ndr::NdrUint32
    end
  end
  describe '#initialize_instance' do
    it 'sets #opnum to LSAR_LOOKUP_SIDS constant' do
      expect(packet.opnum).to eq(RubySMB::Dcerpc::Lsarpc::LSAR_LOOKUP_SIDS)
    end
  end
  it 'reads itself' do
    new_class = described_class.new(
      translated_names: { num_entries: 1, names: [ { use: 0, name: 'Administrator', domain_index: 0 }] },
      mapped_count: 1,
      error_status: 0
    )
    expect(packet.read(new_class.to_binary_s)).to eq(
      referenced_domains: :null,
      translated_names: { num_entries: 1, names: [ { use: 0, name: { buffer_length: 26, maximum_length: 26, buffer: 'Administrator'.encode('UTF-16LE') }, domain_index: 0 } ] },
      mapped_count: 1,
      error_status: 0
    )
  end
end
