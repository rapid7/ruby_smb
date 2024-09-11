RSpec.describe RubySMB::Dcerpc::Wkssvc::NetrWkstaUserEnumResponse do
  subject(:packet) { described_class.new }

  def random_str(nb = 8)
    nb.times.map { rand('a'.ord..'z'.ord).chr }.join
  end

  it { is_expected.to respond_to :user_info }
  it { is_expected.to respond_to :total_entries }
  it { is_expected.to respond_to :result_handle }
  it { is_expected.to respond_to :error_status }

  it 'is little endian' do
    expect(described_class.fields.instance_variable_get(:@hints)[:endian]).to eq :little
  end
  it 'is a BinData::Record' do
    expect(packet).to be_a(BinData::Record)
  end
  describe '#user_info' do
    it 'is a WkstaUserEnumStructure structure' do
      expect(packet.user_info).to be_a RubySMB::Dcerpc::Wkssvc::WkstaUserEnumStructure
    end
  end
  describe '#total_entries' do
    it 'is a NdrUint32Ptr structure' do
      expect(packet.total_entries).to be_a RubySMB::Dcerpc::Ndr::NdrUint32Ptr
    end
  end
  describe '#result_handle' do
    it 'is a NdrUint32Ptr structure' do
      expect(packet.result_handle).to be_a RubySMB::Dcerpc::Ndr::NdrUint32Ptr
    end
  end
  describe '#error_status' do
    it 'is a NdrUint32 structure' do
      expect(packet.error_status).to be_a RubySMB::Dcerpc::Ndr::NdrUint32
    end
  end
  describe '#initialize_instance' do
    it 'sets #opnum to NETR_WKSTA_USER_ENUM constant' do
      expect(packet.opnum).to eq(RubySMB::Dcerpc::Wkssvc::NETR_WKSTA_USER_ENUM)
    end
  end
  it 'reads itself' do
    packet = described_class.new(
      user_info: {
        level: RubySMB::Dcerpc::Wkssvc::WKSTA_USER_INFO_1,
        info: {
          wkui1_entries_read: 1,
          wkui1_buffer: [{
            wkui1_username: random_str,
            wkui1_logon_domain: random_str,
            wkui1_oth_domains: random_str,
            wkui1_logon_server: random_str
          }],
        },
      },
      total_entries: 1,
      result_handle: 0,
      error_status: 0
    )
    binary = packet.to_binary_s
    expect(described_class.read(binary)).to eq(packet)
  end
end
