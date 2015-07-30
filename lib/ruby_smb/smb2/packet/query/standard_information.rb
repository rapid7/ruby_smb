# [[MS-FSCC] 2.4.38 FileStandardInformation](https://msdn.microsoft.com/en-us/library/cc232088.aspx)
class RubySMB::SMB2::Packet::Query::StandardInformation < BitStruct
  default_options endian: 'little'

  unsigned :allocation_size, 64
  unsigned :end_of_file, 64
  unsigned :number_of_links, 32
  unsigned :delete_pending, 8
  unsigned :directory, 8
  unsigned :reserved, 16

end
