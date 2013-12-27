require 'rake/extensiontask'
require 'rake/testtask'

require 'rdoc/task'

require 'rubygems/package_task'

spec = Gem::Specification.load('ruby-lxc.gemspec')
Gem::PackageTask.new(spec) do |pkg|
end

Rake::ExtensionTask.new('lxc', spec) do |ext|
  ext.lib_dir = 'lib/lxc'
end

Rake::RDocTask.new do |rd|
  rd.main = 'ext/lxc/lxc.c'
  rd.rdoc_dir = 'doc'
  rd.rdoc_files.include(FileList['ext/lxc/lxc.c'])
end

Rake::TestTask.new do |t|
  t.libs << 'test'
  t.test_files = FileList['test/test_*.rb']
  t.verbose = true
end
