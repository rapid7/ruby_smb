
require 'smb2/packet/query/standard_information'

class Smb2::File
  attr_accessor :tree
  attr_accessor :create_response

  def initialize(tree:, create_response:)
    self.tree = tree
    self.create_response = create_response
  end

  def close
    packet = Smb2::Packet::CloseRequest.new do |request|
      request.file_id = self.create_response.file_id
    end

    response = tree.send_recv(packet)

    Smb2::Packet::CloseResponse.new(response)
  end

  def read(offset: 0, length: self.create_response.end_of_file)
    packet = Smb2::Packet::ReadRequest.new do |request|
      request.read_offset = offset
      request.read_length = length
      request.file_id = self.create_response.file_id
      request.minimum_count = length
    end

    response = tree.send_recv(packet)

    Smb2::Packet::ReadResponse.new(response)
  end

  def size
    packet = Smb2::Packet::QueryInfoRequest.new do |request|
      request.info_type = 0x01 # SMB2_0_INFO_FILE
      request.file_info_class = Smb2::Packet::FILE_INFORMATION_CLASSES[:FileStandardInformation]
      request.output_buffer_length = 40
      request.input_buffer_length = 0
      request.file_id = self.create_response.file_id
    end
    response = tree.send_recv(packet)
    query_response = Smb2::Packet::QueryInfoResponse.new(response)
    info = Smb2::Packet::Query::StandardInformation.new(query_response.output_buffer)

    info.end_of_file
  end

end
