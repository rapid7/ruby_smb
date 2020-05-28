source 'https://rubygems.org'
gemspec

# separate from test as simplecov is not run on travis-ci
group :coverage do
  # simplecov test formatter and uploader for Coveralls.io
  gem 'coveralls', require: false
  # Coverage reports
  gem 'simplecov', require: false
end

group :test do
  # Testing
  gem 'rspec'
end

group :debug do
  # for development and testing purposes
  gem 'pry-byebug'
  gem 'pry-rescue'
  gem 'pry-stack_explorer'
end

