RSpec.describe RubySMB::Dcerpc::Winreg::Regsam do
  subject(:packet) { described_class.new }

  it { is_expected.to respond_to :reserved }
  it { is_expected.to respond_to :key_create_link }
  it { is_expected.to respond_to :key_notify }
  it { is_expected.to respond_to :key_enumerate_sub_keys }
  it { is_expected.to respond_to :key_create_sub_key }
  it { is_expected.to respond_to :key_set_value }
  it { is_expected.to respond_to :key_query_value }
  it { is_expected.to respond_to :reserved2 }
  it { is_expected.to respond_to :key_wow64_32key }
  it { is_expected.to respond_to :key_wow64_64key }
  it { is_expected.to respond_to :reserved3 }
  it { is_expected.to respond_to :synchronize }
  it { is_expected.to respond_to :write_owner }
  it { is_expected.to respond_to :write_dac }
  it { is_expected.to respond_to :read_control }
  it { is_expected.to respond_to :delete_access }
  it { is_expected.to respond_to :generic_read }
  it { is_expected.to respond_to :generic_write }
  it { is_expected.to respond_to :generic_execute }
  it { is_expected.to respond_to :generic_all }
  it { is_expected.to respond_to :reserved4 }
  it { is_expected.to respond_to :maximum }
  it { is_expected.to respond_to :system_security }


  it 'is little endian' do
    expect(described_class.fields.instance_variable_get(:@hints)[:endian]).to eq :little
  end

  it 'it is a Ndr::NdrStruct' do
    expect(described_class).to be < RubySMB::Dcerpc::Ndr::NdrStruct
  end
end
