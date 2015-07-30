
# [[MS-SMB2] 2.2.37.1 SMB2_QUERY_QUOTA_INFO](https://msdn.microsoft.com/en-us/library/cc246558.aspx)
class RubySMB::SMB2::Packet::Query::QuotaInfo < BitStruct
  default_options endian: 'little'

  unsigned :return_single, 8
  unsigned :restart_scan, 8
  unsigned :reserved, 16
  unsigned :sid_list_length, 32
  unsigned :start_sid_length, 32
  unsigned :start_sid_offset, 32

  rest :sid_buffer
end
