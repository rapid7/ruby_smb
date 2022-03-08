require 'ruby_smb/server/share/provider/processor'

module RubySMB
  class Server
    module Share
      module Provider
        class Disk < Base
          class Processor < Provider::Processor::Base
            module Query
              def do_transactions2_smb1(request)
                local_path = get_local_path(request.data_block.trans2_parameters.fid)

                if local_path.nil?
                  raise NotImplementedError
                end

                response = RubySMB::SMB1::Packet::Trans2::Response.new
              end

              def do_query_directory_smb2(request)
                local_path = get_local_path(request.file_id)
                if local_path.nil?
                  response = RubySMB::SMB2::Packet::ErrorPacket.new
                  response.smb2_header.nt_status = WindowsError::NTStatus::STATUS_FILE_CLOSED
                  return response
                end

                # see: https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/29dfcc9b-3aec-406b-abb5-0b4fe96712e2
                info_class = request.file_information_class.snapshot
                begin
                  # probe #build_info to see if it supports the requested info class
                  build_info(Pathname.new(__FILE__), info_class)
                rescue NotImplementedError
                  logger.warn("Can not handle QUERY_DIRECTORY request for class: #{info_class}")
                  raise
                end

                unless local_path.directory?
                  response = SMB2::Packet::ErrorPacket.new
                  response.smb2_header.nt_status = WindowsError::NTStatus::STATUS_INVALID_PARAMETER
                  return response
                end

                search_pattern = request.name.snapshot.dup.encode
                begin
                  search_regex = wildcard_to_regex(search_pattern)
                rescue NotImplementedError
                  logger.warn("Can not handle QUERY_DIRECTORY wildcard pattern: #{search_pattern}")
                  raise
                end

                return_single = request.flags.return_single == 1

                align = 8
                infos = []
                total_size = 0

                if @query_directory_context[request.file_id.to_binary_s].nil? || request.flags.reopen == 1 || request.flags.restart_scans == 1
                  dirents = local_path.children.sort.to_a
                  dirents.unshift(local_path.parent) unless local_path.parent == local_path
                  dirents.unshift(local_path)
                  @query_directory_context[request.file_id.to_binary_s] = dirents
                else
                  dirents = @query_directory_context[request.file_id.to_binary_s]
                end

                while dirents.length > 0
                  dirent = dirents.shift
                  next unless dirent.file? || dirent.directory? # filter out everything but files and directories

                  case dirent
                  when local_path
                    dirent_name = '.'
                  when local_path.parent
                    dirent_name = '..'
                  else
                    dirent_name = dirent.basename.to_s
                  end
                  next unless search_regex.match?(dirent_name)

                  info = build_info(dirent, info_class, rename: dirent_name)
                  info_size = info.num_bytes + ((align - info.num_bytes % align) % align)
                  if total_size + info_size > request.output_length
                    dirents.unshift(dirent) # no space left for this one so put it back
                    break
                  end

                  infos << info
                  total_size += info_size
                  break if return_single
                end

                if infos.length == 0
                  response = SMB2::Packet::QueryDirectoryResponse.new
                  response.smb2_header.nt_status = WindowsError::NTStatus::STATUS_NO_MORE_FILES
                  return response
                end

                response = SMB2::Packet::QueryDirectoryResponse.new
                infos.last.next_offset = 0 if infos.last
                buffer = ""
                infos.each do |info|
                  info = info.to_binary_s
                  buffer << info + "\x00".b * ((align - info.length % align) % align)
                end
                response.buffer = buffer
                response
              end

              def do_query_info_smb2(request)
                local_path = get_local_path(request.file_id)
                if local_path.nil?
                  response = RubySMB::SMB2::Packet::ErrorPacket.new
                  response.smb2_header.nt_status = WindowsError::NTStatus::STATUS_FILE_CLOSED
                  return response
                end

                case request.info_type
                when SMB2::SMB2_INFO_FILE
                  info = query_info_smb2_file(request, local_path)
                when SMB2::SMB2_INFO_FILESYSTEM
                  info = query_info_smb2_filesystem(request, local_path)
                else
                  logger.warn("Can not handle QUERY_INFO request for type: #{request.info_type}, class: #{request.file_information_class}")
                  raise NotImplementedError
                end

                response = SMB2::Packet::QueryInfoResponse.new
                response.buffer = info.to_binary_s
                response
              end
            end
          end
        end
      end
    end
  end
end
