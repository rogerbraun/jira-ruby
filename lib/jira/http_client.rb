require 'json'
require 'net/https'
require 'net/http/post/multipart'

module JIRA
  class HttpClient < RequestClient

    DEFAULT_OPTIONS = {
      :username           => '',
      :password           => ''
    }

    attr_reader :options

    def initialize(options)
      @options = DEFAULT_OPTIONS.merge(options)
    end

    def make_request(http_method, path, body='', headers={})
      if http_method == :upload
        # Add Atlassian XSRF check bypass header
        headers.merge! 'X-Atlassian-Token' => 'nocheck'

        # XXX: should we raise an exception if file param is blank?
        # XXX: should we detect mime type if none provided?
        # Set filename if none set by caller
        body['filename'] ||= File.basename body['content']

        io = open(body['content'])

        request = Net::HTTP::Post::Multipart.new(path, { 'file' => UploadIO.new(io, body['type'], body['filename']) }, headers)
      else
        request = Net::HTTP.const_get(http_method.to_s.capitalize).new(path, headers)
        request.body = body unless body.nil?
      end

      request.basic_auth(@options[:username], @options[:password])
      response = basic_auth_http_conn.request(request)
      response
    end

    def basic_auth_http_conn
      http_conn(uri)
    end

    def http_conn(uri)
      http_conn = Net::HTTP.new(uri.host, uri.port)
      http_conn.use_ssl = @options[:use_ssl]
      http_conn.verify_mode = @options[:ssl_verify_mode]
      http_conn
    end

    def uri
      uri = URI.parse(@options[:site])
    end
  end
end
