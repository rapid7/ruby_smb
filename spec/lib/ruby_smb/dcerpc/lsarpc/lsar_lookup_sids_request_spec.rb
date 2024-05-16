require 'ruby_smb/dcerpc/ndr'

RSpec.describe RubySMB::Dcerpc::Lsarpc::LsarLookupSidsRequest do
  subject(:packet) { described_class.new }

  it { is_expected.to respond_to :policy_handle }
  it { is_expected.to respond_to :sid_enum_buffer }
  it { is_expected.to respond_to :translated_names }
  it { is_expected.to respond_to :lookup_level }
  it { is_expected.to respond_to :mapped_count }
  it { is_expected.to respond_to :opnum }

  it 'is little endian' do
    expect(described_class.fields.instance_variable_get(:@hints)[:endian]).to eq :little
  end
  it 'is a BinData::Record' do
    expect(packet).to be_a(BinData::Record)
  end
  describe '#policy_handle' do
    it 'is an LsaprHandle structure' do
      expect(packet.policy_handle).to be_a RubySMB::Dcerpc::Lsarpc::LsaprHandle
    end
  end
  describe '#sid_enum_buffer' do
    it 'is an LsaprSidEnumBuffer structure' do
      expect(packet.sid_enum_buffer).to be_a RubySMB::Dcerpc::Lsarpc::LsaprSidEnumBuffer
    end
  end
  describe '#translated_names' do
    it 'is an LsaprTranslatedNames structure' do
      expect(packet.translated_names).to be_a RubySMB::Dcerpc::Lsarpc::LsaprTranslatedNames
    end
  end
  describe '#lookup_level' do
    it 'is an NdrUint16' do
      expect(packet.lookup_level).to be_a RubySMB::Dcerpc::Ndr::NdrUint16
    end
  end
  describe '#mapped_count' do
    it 'is an NdrUint32' do
      expect(packet.mapped_count).to be_a RubySMB::Dcerpc::Ndr::NdrUint32
    end
  end
  describe '#initialize_instance' do
    it 'sets #opnum to LSAR_LOOKUP_SIDS constant' do
      expect(packet.opnum).to eq(RubySMB::Dcerpc::Lsarpc::LSAR_LOOKUP_SIDS)
    end
  end
  it 'reads itself' do
    new_class = described_class.new(
      policy_handle: {
        context_handle_attributes: 0,
        context_handle_uuid: "fc873b90-d9a9-46a4-b9ea-f44bb1c272a7"
      },
      sid_enum_buffer: { num_entries: 1, sid_info: [ { sid: 'S-1-5-21-2181772609-2124839192-2039643012-500' } ] },
      lookup_level: 0,
    )
    expect(packet.read(new_class.to_binary_s)).to eq(
      policy_handle: {
        context_handle_attributes: 0,
        context_handle_uuid: "fc873b90-d9a9-46a4-b9ea-f44bb1c272a7"
      },
      sid_enum_buffer: { num_entries: 1, sid_info: [ { sid: 'S-1-5-21-2181772609-2124839192-2039643012-500' } ] },
      translated_names: { num_entries: 0, names: :null },
      lookup_level: 0,
      mapped_count: 0
    )
  end
end
