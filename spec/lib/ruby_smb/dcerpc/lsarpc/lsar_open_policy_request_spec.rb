require 'ruby_smb/dcerpc/ndr'

RSpec.describe RubySMB::Dcerpc::Lsarpc::LsarOpenPolicyRequest do
  subject(:packet) { described_class.new }

  it { is_expected.to respond_to :system_name }
  it { is_expected.to respond_to :object_attributes }
  it { is_expected.to respond_to :access_mask }
  it { is_expected.to respond_to :opnum }

  it 'is little endian' do
    expect(described_class.fields.instance_variable_get(:@hints)[:endian]).to eq :little
  end
  it 'is a BinData::Record' do
    expect(packet).to be_a(BinData::Record)
  end
  describe '#system_name' do
    it 'is an NdrWideStringPtr structure' do
      expect(packet.system_name).to be_a RubySMB::Dcerpc::Ndr::NdrWideStringPtr
    end
  end
  describe '#object_attributes' do
    it 'is an LsaprObjectAttributes structure' do
      expect(packet.object_attributes).to be_a RubySMB::Dcerpc::Lsarpc::LsaprObjectAttributes
    end
  end
  describe '#access_mask' do
    it 'is an NdrUint32 structure' do
      expect(packet.access_mask).to be_a RubySMB::Dcerpc::Ndr::NdrUint32
    end
  end
  describe '#initialize_instance' do
    it 'sets #opnum to LSAR_OPEN_POLICY constant' do
      expect(packet.opnum).to eq(RubySMB::Dcerpc::Lsarpc::LSAR_OPEN_POLICY)
    end
  end
  it 'reads itself' do
    new_class = described_class.new(
      system_name: 'Example_System',
      object_attributes: {
        security_quality_of_service: {
          impersonation_level: 0,
          security_context_tracking_mode: 0
        }
      },
      access_mask: 0
    )
    expect(packet.read(new_class.to_binary_s)).to eq(
      {
        system_name: 'Example_System'.encode('UTF-16LE'),
        object_attributes: {
          len: 24,
          root_directory: :null,
          object_name: :null,
          attributes: 0,
          security_descriptor: :null,
          security_quality_of_service: {
            len: 12,
            impersonation_level: 0,
            security_context_tracking_mode: 0,
            effective_only: 0
          }
        },
        access_mask: 0
      }
    )
  end
end
