require 'smb2'
Dir["./spec/support/**/*.rb"].sort.each {|f| require f}

# Use find_all_by_name instead of find_by_name as find_all_by_name will return pre-release versions
gem_specification = Gem::Specification.find_all_by_name('metasploit-version').first

Dir[File.join(gem_specification.gem_dir, 'spec', 'support', '**', '*.rb')].each do |f|
  require f
end
