RSpec.describe RubySMB::SMB1::Packet::Generic do

  subject(:packet) { described_class.new }

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
	Flags2                       (Bit16)    Feature Flags2
	Pid_high                     (Bit16)    PID High Bytes
	Security_features            (Bit64)    Security Features
	Reserved                     (Bit16)    Reserved
	Tid                          (Bit16)    Tree ID
	Pid_low                      (Bit16)    PID Low Bytes
	Uid                          (Bit16)    User ID
	Mid                          (Bit16)    Multiplex ID
eos


display = <<-eos

SMB_HEADER
	Protocol ID Field            4283649346
	SMB Command ID               0
	NTStatus Code                0
	Response Packet?             0
	Batch OpLock                 0
	Exclusive Oplock             0
	Canonicalized Pathnames      0
	Pathnames Case Insensitive   0
	Flags Reserved               0
	Receive Buffer Available     0
	Lock&Read Supported          0
	Feature Flags2               0
	PID High Bytes               0
	Security Features            0
	Reserved                     0
	Tree ID                      0
	PID Low Bytes                0
	User ID                      0
	Multiplex ID                 0
eos


  visualizations ={
      description: description.chomp,
      display: display.chomp
  }

  it_behaves_like 'smb generic packet', visualizations

end