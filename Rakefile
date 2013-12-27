require 'rake/extensiontask'

require 'rubygems/package_task'
require 'rspec/core/rake_task'

spec = Gem::Specification.load('ruby-lxc.gemspec')
Gem::PackageTask.new(spec) do |pkg|
end

Rake::ExtensionTask.new('lxc', spec) do |ext|
  ext.lib_dir = 'lib/lxc'
end

RSpec::Core::RakeTask.new(:spec) do |t|
  t.pattern = %w{spec/**/*_spec.rb}
end
