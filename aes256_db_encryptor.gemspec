# frozen_string_literal: true

require_relative "lib/aes256_db_encryptor/version"

Gem::Specification.new do |spec|
  spec.name = "aes256_db_encryptor"
  spec.version = Aes256DbEncryptor::VERSION
  spec.authors = ["Neeraj Pathak"]
  spec.email = ["neeraj.pathak@infobeans.com"]

  spec.summary = "AES 256 algorithm to encrypt and decrypt data"
  spec.description = "AES 256 algorithm to encrypt and decrypt data"
  spec.homepage = "https://github.com/infobeans-neeraj/aes256_db_encryptor"
  spec.required_ruby_version = ">= 3.0.0"

  spec.metadata["allowed_push_host"] = "https://example.com"

  spec.metadata["homepage_uri"] = spec.homepage
  spec.metadata["source_code_uri"] = "https://github.com/infobeans-neeraj/aes256_db_encryptor"
  spec.metadata["changelog_uri"] = "https://github.com/infobeans-neeraj/aes256_db_encryptor"

  # Specify which files should be added to the gem when it is released.
  # The `git ls-files -z` loads the files in the RubyGem that have been added into git.
  gemspec = File.basename(__FILE__)
  spec.files = IO.popen(%w[git ls-files -z], chdir: __dir__, err: IO::NULL) do |ls|
    ls.readlines("\x0", chomp: true).reject do |f|
      (f == gemspec) ||
        f.start_with?(*%w[bin/ test/ spec/ features/ .git appveyor Gemfile])
    end
  end
  spec.bindir = "exe"
  spec.executables = spec.files.grep(%r{\Aexe/}) { |f| File.basename(f) }
  spec.require_paths = ["lib"]
  spec.add_dependency "rails", ">= 5.0"
  spec.add_dependency "activerecord"
  spec.add_dependency "openssl"
  spec.add_dependency "base64"
  spec.add_development_dependency "rspec"
  # Uncomment to register a new dependency of your gem
  # spec.add_dependency "example-gem", "~> 1.0"

  # For more information and examples about making a new gem, check out our
  # guide at: https://bundler.io/guides/creating_gem.html
end
