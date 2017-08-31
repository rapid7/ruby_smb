RSpec.describe RubySMB::SMB1::BitField::FileStatusFlags do
  subject(:options) { described_class.new }

  it { is_expected.to respond_to :reparse_tag }
  it { is_expected.to respond_to :no_substreams }
  it { is_expected.to respond_to :no_eas }

  it 'is little endian' do
    expect(described_class.fields.instance_variable_get(:@hints)[:endian]).to eq :little
  end

  {
    :reparse_tag    => 0x0004,
    :no_substreams  => 0x0002,
    :no_eas         => 0x0001
  }.each do |field, bitmask|
    describe "##{field.to_s}" do
      it 'is a 1-bit flag' do
        expect(options.send(field)).to be_a BinData::Bit1
      end

      it_behaves_like 'bit field with one flag set', field, 'v', bitmask
    end
  end
end

