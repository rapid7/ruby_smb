RSpec.describe RubySMB::Dcerpc::Samr::SamrOpenDomainRequest do
  subject(:packet) { described_class.new }

  it { is_expected.to respond_to :server_handle }
  it { is_expected.to respond_to :desired_access }
  it { is_expected.to respond_to :domain_id }
  it { is_expected.to respond_to :opnum }

  it 'is little endian' do
    expect(described_class.fields.instance_variable_get(:@hints)[:endian]).to eq :little
  end
  it 'is a BinData::Record' do
    expect(packet).to be_a(BinData::Record)
  end
  describe '#server_handle' do
    it 'is a SamprHandle structure' do
      expect(packet.server_handle).to be_a RubySMB::Dcerpc::Samr::SamprHandle
    end
  end
  describe '#desired_access' do
    it 'is a NdrUint32 structure' do
      expect(packet.desired_access).to be_a RubySMB::Dcerpc::Ndr::NdrUint32
    end
  end
  describe '#domain_id' do
    it 'is a RpcSid structure' do
      expect(packet.domain_id).to be_a RubySMB::Dcerpc::Samr::RpcSid
    end
  end
  describe '#initialize_instance' do
    it 'sets #opnum to SAMR_OPEN_DOMAIN constant' do
      expect(packet.opnum).to eq(RubySMB::Dcerpc::Samr::SAMR_OPEN_DOMAIN)
    end
  end
  it 'reads itself' do
    new_class = described_class.new(
      server_handle: {
        context_handle_attributes: 0,
        context_handle_uuid: '2ef54a87-e29e-4d24-90e9-9da49b94449e'
      },
      desired_access: 555,
      domain_id: 'S-1-5-21-419547006-9459028-4093171872-500'
    )
    expect(packet.read(new_class.to_binary_s)).to eq(
      {
        server_handle: {
          context_handle_attributes: 0,
          context_handle_uuid: '2ef54a87-e29e-4d24-90e9-9da49b94449e'
        },
        desired_access: 555,
        domain_id: 'S-1-5-21-419547006-9459028-4093171872-500'
      }
    )
  end
end

