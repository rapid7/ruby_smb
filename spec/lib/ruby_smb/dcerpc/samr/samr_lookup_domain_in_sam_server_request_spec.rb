RSpec.describe RubySMB::Dcerpc::Samr::SamrLookupDomainInSamServerRequest do
  subject(:packet) { described_class.new }

  it { is_expected.to respond_to :server_handle }
  it { is_expected.to respond_to :name }
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
  describe '#name' do
    it 'is a RpcUnicodeString structure' do
      expect(packet.name).to be_a RubySMB::Dcerpc::RpcUnicodeString
    end
  end
  describe '#initialize_instance' do
    it 'sets #opnum to SAMR_LOOKUP_DOMAIN_IN_SAM_SERVER constant' do
      expect(packet.opnum).to eq(RubySMB::Dcerpc::Samr::SAMR_LOOKUP_DOMAIN_IN_SAM_SERVER)
    end
  end
  it 'reads itself' do
    new_class = described_class.new(
      server_handle: {
        context_handle_attributes: 0,
        context_handle_uuid: '2ef54a87-e29e-4d24-90e9-9da49b94449e'
      },
      name: 'Test Server Name'
    )
    expect(packet.read(new_class.to_binary_s)).to eq(
      {
        server_handle: {
          context_handle_attributes: 0,
          context_handle_uuid: '2ef54a87-e29e-4d24-90e9-9da49b94449e'
        },
        name: {
          buffer_length: 32,
          maximum_length: 32,
          buffer: 'Test Server Name'.encode('utf-16le')
        }
      }
    )
  end
end

