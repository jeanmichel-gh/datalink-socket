# frozen_string_literal: true

require "rake/testtask"

Rake::TestTask.new(:test) do |t|
  t.libs << "lib" << "test"
  t.test_files = FileList["test/**/test_*.rb"]
  t.warning = false
end

namespace :test do
  Rake::TestTask.new(:unit) do |t|
    t.libs << "lib" << "test"
    t.test_files = FileList["test/unit/test_*.rb"]
  end

  Rake::TestTask.new(:functional) do |t|
    t.libs << "lib" << "test"
    t.test_files = FileList["test/functional/test_*.rb"]
  end
end

task default: :test
