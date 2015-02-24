module Last
module Authenticators

class AccountAuthenticator
  UUID_EXPRESSION = /\A[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\z/i.freeze

  def initialize(env)
    @authorization_header = env['HTTP_AUTHORIZATION']
  end

  def call
    raise AuthenticationError unless authenticated?
    self
  end

  def authenticated?
    account ? true : false
  end

  def account
    @_account ||=
      valid_access_token? ? self.class.account_getter.call(access_token) : nil
  end

private

  attr_reader :authorization_header

  def access_token
    @_access_token ||=
      authorization_header ? authorization_header.split.last : nil
  end

  def valid_access_token?
    @_valid_access_token ||=
      UUID_EXPRESSION.match(access_token)
  end

  def self.set_account_getter(&block)
    @account_getter = block
  end

  class << self
    attr_reader :account_getter
  end
end

class AccountAuthenticator::AuthenticationError < StandardError
  define_method(:http_status) { 401 }
  define_method(:message)     { "Unauthorized" }
end

end
end
