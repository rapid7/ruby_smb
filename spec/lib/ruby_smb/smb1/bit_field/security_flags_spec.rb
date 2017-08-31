RSpec.describe RubySMB::SMB1::BitField::SecurityFlags do
  subject(:options) { described_class.new }

      it { is_expected.to respond_to :effective_only }
      it { is_expected.to respond_to :context_tracking }

  it 'is little endian' do
    expect(described_class.fields.instance_variable_get(:@hints)[:endian]).to eq :little
  end

  {
    :effective_only   => 0x02,
    :context_tracking => 0x01
  }.each do |field, bitmask|
    describe "##{field.to_s}" do
      it 'is a 1-bit flag' do
        expect(options.send(field)).to be_a BinData::Bit1
      end

      it_behaves_like 'bit field with one flag set', field, 'C', bitmask
    end
  end
end



