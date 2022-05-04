module RubySMB
  module Fscc
    module FileInformation
      # The FileModeInformation Class as defined in
      # [2.4.26 FileModeInformation](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-fscc/52df7798-8330-474b-ac31-9afe8075640c)
      class FileModeInformation < BinData::Record
        CLASS_LEVEL = FileInformation::FILE_MODE_INFORMATION

        endian :little

        struct  :flags do
          bit2   :reserved
          bit1   :file_synchronous_io_nonalert,   label: 'File Synchronous IO Nonalert'
          bit1   :file_synchronous_io_alert,      label: 'File Synchronous IO Alert'
          bit1   :file_no_intermediate_buffering, label: 'File No Intermediate Buffering'
          bit1   :file_sequential_only,           label: 'File Sequential Only'
          bit1   :file_write_through,             label: 'File Write Through'
          bit1   :reserved2
          # byte boundary
          bit3   :reserved3
          bit1   :file_delete_on_close,           label: 'File Delete On Close'
          bit4   :reserved4
          # byte boundary
          bit16  :reserved5
        end
      end
    end
  end
end
