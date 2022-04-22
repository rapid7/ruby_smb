module RubySMB
  module Fscc
    module FileSystemInformation
      # The FileFsVolumeInformation
      # [2.5.9 FileFsVolumeInformation](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-fscc/bf691378-c34e-4a13-976e-404ea1a87738)
      class FileFsVolumeInformation < BinData::Record
        CLASS_LEVEL = FileSystemInformation::FILE_FS_VOLUME_INFORMATION

        endian :little

        file_time :volume_creation_time, label: 'Volume Creation Time'
        uint32    :volume_serial_number, label: 'Volume Serial Number'
        uint32    :volume_label_length,  label: 'Volume Label Length', initial_value: -> { volume_label.do_num_bytes }
        uint8     :supports_objects,     label: 'Supports Objects'
        uint8     :reserved,             label: 'Reserved'
        string16  :volume_label,         label: 'Volume Label', read_length: -> { volume_label_length }
      end
    end
  end
end
