class Smb2::Packet::Query::NamesInformation < BitStruct

  default_options endian: 'little'

  unsigned :next_entry_offset, 32
  unsigned :file_index, 32
  unsigned :file_name_length, 32
  rest :file_name

end
