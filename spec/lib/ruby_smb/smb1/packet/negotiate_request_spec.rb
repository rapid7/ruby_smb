RSpec.describe RubySMB::SMB1::Packet::NegotiateRequest do

  subject(:packet) { described_class.new }
  let(:dialect_string) { 'NT LM 0.12' }

  before(:each) {
    packet.add_dialect(dialect_string)
  }

description = <<-eos

SMB_HEADER#{' '*31}
	Protocol                     (Bit32)    Protocol ID Field
	Command                      (Bit8)     SMB Command ID
	Nt_status                    (Bit32)    NTStatus Code
	Flags_reply                  (Bit1)     Response Packet?
	Flags_opbatch                (Bit1)     Batch OpLock
	Flags_oplock                 (Bit1)     Exclusive Oplock
	Flags_canonicalized_paths    (Bit1)     Canonicalized Pathnames
	Flags_case_insensitive       (Bit1)     Pathnames Case Insensitive
	Flags_reserved               (Bit1)     Flags Reserved
	Flags_buf_avail              (Bit1)     Receive Buffer Available
	Flags_lock_and_read_ok       (Bit1)     Lock&Read Supported
	Flags2_unicode               (Bit1)     Unicode Strings
	Flags2_nt_status             (Bit1)     NTStatus Errors
	Flags2_paging_io             (Bit1)     Read if Execute
	Flags2_dfs                   (Bit1)     Use DFS
	Flags2_extended_security     (Bit1)     Extended Security
	Flags2_reparse_path          (Bit1)     @GMT Token Required
	Flags2_reserved1             (Bit3)     Reserved
	Flags2_is_long_name          (Bit1)     Long Names Used
	Flags2_reserved2             (Bit1)     Reserved
	Flags2_signature_required    (Bit1)     Security Signature Required
	Flags2_compressed            (Bit1)     Compressed
	Flags2_security_signature    (Bit1)     Security Signing
	Flags2_eas                   (Bit1)     Extended Attributes
	Flags2_long_names            (Bit1)     Long Names Allowed
	Pid_high                     (Bit16)    PID High Bytes
	Security_features            (Bit64)    Security Features
	Reserved                     (Bit16)    Reserved
	Tid                          (Bit16)    Tree ID
	Pid_low                      (Bit16)    PID Low Bytes
	Uid                          (Bit16)    User ID
	Mid                          (Bit16)    Multiplex ID
PARAMETER_BLOCK#{' '*26}
	Word_count                   (Uint8)    Word Count
DATA_BLOCK#{' '*31}
	Byte_count                   (Uint16le) Byte Count
	Dialects                     (Array)    Dialects
  eos


display = <<-eos

SMB_HEADER
	Protocol ID Field            4283649346
	SMB Command ID               #{RubySMB::SMB1::Commands::SMB_COM_NEGOTIATE}
	NTStatus Code                0
	Response Packet?             0
	Batch OpLock                 0
	Exclusive Oplock             0
	Canonicalized Pathnames      1
	Pathnames Case Insensitive   1
	Flags Reserved               0
	Receive Buffer Available     0
	Lock&Read Supported          0
	Unicode Strings              1
	NTStatus Errors              1
	Read if Execute              0
	Use DFS                      0
	Extended Security            0
	@GMT Token Required          0
	Reserved                     0
	Long Names Used              0
	Reserved                     0
	Security Signature Required  0
	Compressed                   0
	Security Signing             0
	Extended Attributes          0
	Long Names Allowed           0
	PID High Bytes               0
	Security Features            0
	Reserved                     0
	Tree ID                      0
	PID Low Bytes                0
	User ID                      0
	Multiplex ID                 0
PARAMETER_BLOCK
	Word Count                   0
DATA_BLOCK
	Byte Count                   12
	DIALECTS
		Buffer Format ID            2
		Dialect Name                NT LM 0.12
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

    it 'should not have the response flag set' do
      expect(header.flags_reply).to eq 0
    end
  end

  describe '#parameter_block' do
    subject(:parameter_block) { packet.parameter_block }

    it 'is a standard ParameterBlock' do
      expect(parameter_block).to be_a RubySMB::SMB1::Packet::ParameterBlock
    end
  end

  describe '#data_block' do
    subject(:data_block) { packet.data_block }

    it 'is a standard DataBlock' do
      expect(data_block).to be_a RubySMB::SMB1::Packet::DataBlock
    end

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