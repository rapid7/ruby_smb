RSpec.describe RubySMB::SMB1::Packet::NegotiateRequest do

  subject(:packet) { described_class.new }
  let(:dialect_string) { 'NT LM 0.12' }

  before(:each) {
    packet.add_dialect(dialect_string)
  }

description = <<-eos

SMB_HEADER#{' '*21}
	Protocol           (Bit32)    Protocol ID Field
	Command            (Bit8)     SMB Command ID
	Nt_status          (Bit32)    NTStatus Code
	Flags              (Bit8)     Feature Flags
	Flags2             (Bit16)    Feature Flags2
	Pid_high           (Bit16)    PID High Bytes
	Security_features  (Bit64)    Security Features
	Reserved           (Bit16)    Reserved
	Tid                (Bit16)    Tree ID
	Pid_low            (Bit16)    PID Low Bytes
	Uid                (Bit16)    User ID
	Mid                (Bit16)    Multiplex ID
PARAMETER_BLOCK#{' '*16}
	Word_count         (Uint8)    Word Count
DATA_BLOCK#{' '*21}
	Byte_count         (Uint16le) Byte Count
	Dialects           (Array)    Dialects
  eos


display = <<-eos

SMB_HEADER
	Protocol ID Field  4283649346
	SMB Command ID     #{RubySMB::SMB1::Commands::SMB_COM_NEGOTIATE}
	NTStatus Code      0
	Feature Flags      0
	Feature Flags2     0
	PID High Bytes     0
	Security Features  0
	Reserved           0
	Tree ID            0
	PID Low Bytes      0
	User ID            0
	Multiplex ID       0
PARAMETER_BLOCK
	Word Count         0
DATA_BLOCK
	Byte Count         12
	DIALECTS
		Buffer Format ID  2
		Dialect Name      NT LM 0.12
  eos

  visualizations ={
    description: description.chomp,
    display: display.chomp
  }

  it_behaves_like 'smb generic packet', visualizations

  describe '#smb_header' do
    subject(:header) { packet.smb_header }

    it 'should have the command set to SMB_COM_NEGOTIATE' do
      expect(header.command).to eq RubySMB::SMB1::Commands::SMB_COM_NEGOTIATE
    end
  end

  describe '#parameter_block' do
    subject(:parameter_block) { packet.parameter_block }

    it_behaves_like 'smb parameter block'
  end

  describe '#data_block' do
    subject(:data_block) { packet.data_block }

    it_behaves_like 'smb data block'

    it { is_expected.to respond_to :dialects }

    describe '#dialects' do
      it 'is an array field as per the SMB spec'do
        expect(data_block.dialects).to be_a BinData::Array
      end
    end
  end

  describe '#add_dialect' do
    it 'adds a Dialect to the packet' do
      expect{ packet.add_dialect('foo') }.to change{ packet.data_block.dialects.count }.by(1)
    end

    it 'uses the argument as the Dialect String' do
      packet.add_dialect('bar')
      dialects = packet.data_block.dialects.to_a
      expect(dialects.last.dialect_string).to eq 'bar'
    end
  end

  describe '#set_dialects' do
    it 'clears out any existing dialects' do
      expect{ packet.set_dialects([])}.to change{ packet.data_block.dialects.count }.to(0)
    end

    it 'calls #add_dialect once for each string in the array' do
      expect(packet).to receive(:add_dialect).exactly(3).times
      packet.set_dialects(['foo','bar','baz'])
    end
  end

end