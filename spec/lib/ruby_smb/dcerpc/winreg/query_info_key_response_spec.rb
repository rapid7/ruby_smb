RSpec.describe RubySMB::Dcerpc::Winreg::QueryInfoKeyResponse do
  subject(:packet) { described_class.new }

  it { is_expected.to respond_to :lp_class }
  it { is_expected.to respond_to :lpc_sub_keys }
  it { is_expected.to respond_to :lpc_max_sub_key_len }
  it { is_expected.to respond_to :lpc_max_class_len }
  it { is_expected.to respond_to :lpc_values }
  it { is_expected.to respond_to :lpcb_max_value_name_len }
  it { is_expected.to respond_to :lpcb_max_value_len }
  it { is_expected.to respond_to :lpcb_security_descriptor }
  it { is_expected.to respond_to :lpft_last_write_time }
  it { is_expected.to respond_to :error_status }
  it { is_expected.to respond_to :opnum }

  it 'is little endian' do
    expect(described_class.fields.instance_variable_get(:@hints)[:endian]).to eq :little
  end

  describe '#lp_class' do
    it 'is a RrpUnicodeString structure' do
      expect(packet.lp_class).to be_a RubySMB::Dcerpc::RrpUnicodeString
    end

    it 'has the expected initial value' do
      expect(packet.lp_class).to eq({:buffer_length=>0, :maximum_length=>0, :buffer=>:null})
    end
  end

  describe '#lpc_sub_keys' do
    it 'is a NdrUint32' do
      expect(packet.lpc_sub_keys).to be_a RubySMB::Dcerpc::Ndr::NdrUint32
    end
  end

  describe '#lpc_max_sub_key_len' do
    it 'is a NdrUint32' do
      expect(packet.lpc_max_sub_key_len).to be_a RubySMB::Dcerpc::Ndr::NdrUint32
    end
  end

  describe '#lpc_max_class_len' do
    it 'is a NdrUint32' do
      expect(packet.lpc_max_class_len).to be_a RubySMB::Dcerpc::Ndr::NdrUint32
    end
  end

  describe '#lpc_values' do
    it 'is a NdrUint32' do
      expect(packet.lpc_values).to be_a RubySMB::Dcerpc::Ndr::NdrUint32
    end
  end

  describe '#lpcb_max_value_name_len' do
    it 'is a NdrUint32' do
      expect(packet.lpcb_max_value_name_len).to be_a RubySMB::Dcerpc::Ndr::NdrUint32
    end
  end

  describe '#lpcb_max_value_len' do
    it 'is a NdrUint32' do
      expect(packet.lpcb_max_value_len).to be_a RubySMB::Dcerpc::Ndr::NdrUint32
    end
  end

  describe '#lpcb_security_descriptor' do
    it 'is a NdrUint32' do
      expect(packet.lpcb_security_descriptor).to be_a RubySMB::Dcerpc::Ndr::NdrUint32
    end
  end

  describe '#lpft_last_write_time' do
    it 'is a NdrFileTime structure' do
      expect(packet.lpft_last_write_time).to be_a RubySMB::Dcerpc::Ndr::NdrFileTime
    end
  end

  describe '#error_status' do
    it 'is a NdrUint32' do
      expect(packet.error_status).to be_a RubySMB::Dcerpc::Ndr::NdrUint32
    end
  end

  describe '#initialize_instance' do
    it 'sets #opnum to REG_QUERY_INFO_KEY constant' do
      expect(packet.opnum).to eq(RubySMB::Dcerpc::Winreg::REG_QUERY_INFO_KEY)
    end
  end
end
