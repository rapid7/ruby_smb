RSpec.describe RubySMB::SMB1::BitField::NtCreateAndxFlags do
  subject(:options) { described_class.new }

  it { is_expected.to respond_to :request_extended_response }
  it { is_expected.to respond_to :open_target_dir }
  it { is_expected.to respond_to :request_opbatch }
  it { is_expected.to respond_to :request_oplock }

  it 'is little endian' do
    expect(described_class.fields.instance_variable_get(:@hints)[:endian]).to eq :little
  end

  {
    :request_extended_response => 0x00000010,
    :open_target_dir           => 0x00000008,
    :request_opbatch           => 0x00000004,
    :request_oplock            => 0x00000002
  }.each do |field, bitmask|
    describe "##{field.to_s}" do
      it 'is a 1-bit flag' do
        expect(options.send(field)).to be_a BinData::Bit1
      end

      it_behaves_like 'bit field with one flag set', field, 'V', bitmask
    end
  end
end


