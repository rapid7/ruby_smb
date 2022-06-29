RSpec.describe RubySMB::Dcerpc::Samr::SamrLookupNamesInDomainRequest do
  subject(:packet) { described_class.new }

  it { is_expected.to respond_to :domain_handle }
  it { is_expected.to respond_to :names_count }
  it { is_expected.to respond_to :names }
  it { is_expected.to respond_to :opnum }

  it 'is little endian' do
    expect(described_class.fields.instance_variable_get(:@hints)[:endian]).to eq :little
  end

  it 'is a BinData::Record' do
    expect(packet).to be_a(BinData::Record)
  end

  describe '#domain_handle' do
    it 'is a SamprHandle structure' do
      expect(packet.domain_handle).to be_a RubySMB::Dcerpc::Samr::SamprHandle
    end
  end

  describe '#names_count' do
    it 'is a NdrUint32 structure' do
      expect(packet.names_count).to be_a RubySMB::Dcerpc::Ndr::NdrUint32
    end
  end

  describe '#names' do
    it 'is a RpcUnicodeStringConfVarArray structure' do
      expect(packet.names).to be_a RubySMB::Dcerpc::RpcUnicodeStringConfVarArray
    end
  end

  describe '#initialize_instance' do
    it 'sets #opnum to SAMR_LOOKUP_NAMES_IN_DOMAIN constant' do
      expect(packet.opnum).to eq(RubySMB::Dcerpc::Samr::SAMR_LOOKUP_NAMES_IN_DOMAIN)
    end
  end

  it 'reads itself' do
    new_packet = described_class.new({
      domain_handle: {
        context_handle_attributes: 0,
        context_handle_uuid: "fc873b90-d9a9-46a4-b9ea-f44bb1c272a7"
      },
      names_count: 1,
      names: [ 'TEST' ]
    })
    expected_output = {
      domain_handle: {
        context_handle_attributes: 0,
        context_handle_uuid: "fc873b90-d9a9-46a4-b9ea-f44bb1c272a7"
      },
      names_count: 1,
      names: [
        { buffer_length: 8, maximum_length: 8, buffer: "TEST".encode('utf-16le') }
      ]
    }
    expect(packet.read(new_packet.to_binary_s)).to eq(expected_output)
  end
end
