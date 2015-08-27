RSpec.describe RubySMB::SMB1::Packet::Generic do

  subject(:packet) { described_class.new }

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
eos


display = <<-eos

SMB_HEADER
	Protocol ID Field  4283649346
	SMB Command ID     0
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
eos


  visualizations ={
      description: description.chomp,
      display: display.chomp
  }

  it_behaves_like 'smb generic packet', visualizations

end