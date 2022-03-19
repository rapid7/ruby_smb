module RubySMB
  module Fscc
    module FileInformation
      # The FileAllInformation Class as defined in
      # [2.4.2 FileAllInformation](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-fscc/95f3056a-ebc1-4f5d-b938-3f68a44677a6)
      class FileAllInformation < BinData::Record
        CLASS_LEVEL = FileInformation::FILE_ALL_INFORMATION

        endian :little

        file_basic_information      :basic_information,     label: 'Basic Information'
        file_standard_information   :standard_information,  label: 'Standard Information'
        file_internal_information   :internal_information,  label: 'Internal Information'
        file_ea_information         :ea_information,        label: 'EA Information'
        file_access_information     :access_information,    label: 'Access Information'
        file_position_information   :position_information,  label: 'Position Information'
        file_mode_information       :mode_information,      label: 'Mode Information'
        file_alignment_information  :alignment_information, label: 'Alignment Information'
        file_name_information       :name_information,      label: 'Label Information'
      end
    end
  end
end
