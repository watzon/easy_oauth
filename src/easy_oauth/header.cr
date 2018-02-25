require "uri"
require "random"
require "base64"
require "openssl/hmac"
require "http/params"

require "../core_ext/*"

module EasyOAuth
  class Header
    ATTRIBUTE_KEYS = ["callback", "consumer_key", "nonce", "signature_method", "timestamp", "token", "verifier", "version"]

    IGNORED_KEYS = ["consumer_secret", "token_secret", "signature"]

    getter :method, :params, :options

    @method : String
    @uri : URI
    @params : Hash(String, String)
    @options : Hash(String, String) = {} of String => String

    def initialize(method, url, params, oauth = {} of String => String)
      @method = method.to_s
      @uri = url.is_a?(URI) ? url : URI.parse(url)
      @uri.scheme = @uri.scheme ? @uri.scheme.not_nil!.downcase : "https"
      @uri.normalize!
      @uri.fragment = nil
      @params = params
      @options = oauth.is_a?(Hash) ? Header.default_options.merge(oauth) : Header.parse(oauth)
    end

    def method
      @method.upcase
    end

    def url
      uri = @uri.dup
      uri.host = uri.host.not_nil!.downcase unless uri.host.nil?
      uri.query = nil
      uri.to_s
    end

    def to_s
      "OAuth #{normalized_attributes}"
    end

    def valid?(secrets = {} of String => String)
      original_options = @options.dup
      options.merge!(secrets)
      valid = options["signature"]? == signature
      @options = original_options
      valid
    end

    def signed_attributes(attrs = attributes)
      attrs.merge({ "oauth_signature" => signature })
    end

    def normalized_attributes(attrs = signed_attributes)
      attrs.sort.map { |k, v| %(#{k}="#{Header.escape(v)}") }.join(", ")
    end

    def attributes
      matching_keys, extra_keys = @options.keys.partition { |key| ATTRIBUTE_KEYS.includes?(key) }
      extra_keys -= IGNORED_KEYS
      if !!options["ignore_extra_keys"]? || extra_keys.empty?
        options.select { |key, _| matching_keys.includes?(key) }.map { |key, value| ["oauth_#{key}", value] }.to_h
      else
        raise "EasyOAuth: Found extra option keys not matching ATTRIBUTE_KEYS:\n  [other]"
      end
    end

    def signature
      # send(options["signature_method"].downcase.tr("-", "_") + "_signature")
      case options["signature_method"].downcase
      when "hmac-sha1"
        hmac_sha1_signature
      when "plaintext"
        plaintext_signature
      else raise "signature method #{options["signature_method"]} not supported"
      end
    end

    def hmac_sha1_signature
      Base64.encode(OpenSSL::HMAC.digest(:sha1, secret, signature_base)).chomp.gsub(/\n/, "")
    end

    def plaintext_signature
      secret
    end

    def secret
      options.values_at?("consumer_secret", "token_secret").map { |v| Header.escape(v) }.join("&")
    end

    def signature_base
      [method, url, normalized_params].map { |v| Header.escape(v) }.join("&")
    end

    def normalized_params
      signature_params.map { |p| p.map { |v| Header.escape(v) } }.map { |p| p.join("=") }.sort.join("&")
    end

    def signature_params
      attributes.to_a + params.to_a + url_params
    end

    def url_params
      HTTP::Params.parse(@uri.query || "")
        .reduce([] of Array(String)) { |p, (k, v)| p.push([k,v]) }.sort
    end

    def self.default_options
      {
        "nonce" => Random.new.random_bytes(16).hexstring,
        "signature_method" => "HMAC-SHA1",
        "timestamp" => Time.now.epoch.to_s,
        "version" => "1.0"
      }
    end

    def self.parse(header)
      unless (header.is_a?(String))
        header = header.to_s
      end

      header.sub(/^OAuth\s/, "").split(/,\s*/).reduce({} of String => String) do |attrs, pair|
        match = pair.match(/^(\w+)\=\"([^\"]*)\"$/).not_nil!
        attrs.merge({ match[1].sub(/^oauth_/, "") => unescape(match[2]) })
      end
    end

    def Header.escape(value)
      URI.escape(value.to_s)
    end

    def self.unescape(value)
      URI.unescape(value.to_s)
    end
  end
end
