#
module Smb2::Packet::Query
  autoload :NamesInformation, 'smb2/packet/query/names_information'
  autoload :StandardInformation, 'smb2/packet/query/standard_information'

  # Number of bytes in a StandardInformation packet.
  STANDARD_INFORMATION_SIZE = 40

  FILE_INFORMATION_CLASSES = {
    FileDirectoryInformation: nil,
    FileFullDirectoryInformation: nil,
    FileIdFullDirectoryInformation: nil,
    FileBothDirectoryInformation: nil,
    FileIdBothDirectoryInformation: nil,
    FileBothDirectoryInformation: nil,
    FileNamesInformation: NamesInformation
  }

  def self.class_array_from_blob(blob, klass)
    class_array = []
    offset = 0

    loop do
      length = blob[offset, 4].unpack('V').first

      if length.zero?
        data = blob[offset..-1]
      else
        data = blob[offset, length]
      end

      class_array << klass.new(data)
      offset += length

      break if length.zero? || offset > blob.length
    end

    class_array
  end
end
