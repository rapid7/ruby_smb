# [[MS-FSCC] 2.4.26 FileNamesInformation](https://msdn.microsoft.com/en-us/library/cc232077.aspx)
class Smb2::Packet::Query::NamesInformation < BitStruct

  default_options endian: 'little'

  unsigned :next_entry_offset, 32
  unsigned :file_index, 32
  unsigned :file_name_length, 32
  rest :raw_file_name

  def file_name
    raw_file_name[0, file_name_length].encode('utf-8', 'utf-16le')
  end

end
