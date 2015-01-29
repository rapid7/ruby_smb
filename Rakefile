require 'bundler/gem_tasks'

require 'rspec/core/rake_task'

require 'yard'
require 'yard/rake/yardoc_task'

RSpec::Core::RakeTask.new(:spec)

YARD::Rake::YardocTask.new do |t|
  t.options = [ '-m', 'markdown' ]
  t.options += Dir.glob('yard_extensions/*.rb').map { |e| [ '-e', e ] }.flatten
  t.files = ['lib/**/*.rb', '-', 'README.md', 'LICENSE.txt']
end

task :default => :spec
