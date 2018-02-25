require "../spec_helper"

describe EasyOAuth::Header do
  describe ".default_options" do
    let(default_options) { EasyOAuth::Header.default_options }

    it "is different every time" do
      expect(default_options).not_to eq EasyOAuth::Header.default_options
    end

    it "is used for new headers" do
      header = EasyOAuth::Header.new(:get, "https://api.twitter.com/1/statuses/friendships.json", {} of String => String)
      expect(header.options.reject("nonce")).to eq default_options.reject("nonce")
    end

    it "ignores a signature method and OAuth version" do
      expect(default_options["signature_method"]).not_to be_nil
      expect(default_options["version"]).not_to be_nil
    end
  end

  describe ".escape" do
    it "escapes (most) non-word characters" do
      [" ", "!", "@", "#", "$", "%", "^", "&"].each do |character|
        escaped = EasyOAuth::Header.escape(character)
        expect(escaped).not_to eq character
        expect(escaped).to eq URI.escape(character)
      end
    end

    it "does not escape - . or ~" do
      ["-", ".", "~"].each do |character|
        escaped = EasyOAuth::Header.escape(character)
        expect(escaped).to eq character
      end
    end

    it "escapes non-ASCII characters" do
      expect(EasyOAuth::Header.escape("é")).to eq "%C3%A9"
    end

    it "escapes multibyte characters" do
      expect(EasyOAuth::Header.escape("あ")).to eq "%E3%81%82"
    end
  end

  describe ".unescape" do
    pending "unescapes standard ASCII characters"

    pending "unescapes non-ASCII characters"

    pending "unescapes multibyte characters"
  end

  describe ".parse" do
    let(header) { EasyOAuth::Header.new(:get, "https://api.twitter.com/1/statuses/friends.json", {} of String => String) }
    let(parsed_options) { EasyOAuth::Header.parse(header) }

    it "returns a hash" do
      expect(parsed_options.is_a?(Hash)).to be_true
    end

    it "includes the options used to build the header" do
      expect(parsed_options.reject("signature")).to eq header.options
    end

    it "includes a signature" do
      expect(header.options.has_key?("signature")).to be_false
      expect(parsed_options.has_key?("signature")).to be_true
      expect(parsed_options["signature"]?).not_to be_nil
    end

    it "handles optional 'linear white space'" do
      parsed_header_with_spaces = EasyOAuth::Header.parse %{OAuth oauth_consumer_key="abcd", oauth_nonce="oLKtec51GQy", oauth_signature="efgh%26mnop", oauth_signature_method="PLAINTEXT", oauth_timestamp="1286977095", oauth_token="ijkl", oauth_version="1.0"}
      expect(parsed_header_with_spaces).to be_a(Hash(String, String))
      expect(parsed_header_with_spaces.keys.size).to eq 7

      parsed_header_with_tabs = EasyOAuth::Header.parse %{OAuth oauth_consumer_key="abcd", oauth_nonce="oLKtec51GQy",  oauth_signature="efgh%26mnop",  oauth_signature_method="PLAINTEXT", oauth_timestamp="1286977095", oauth_token="ijkl", oauth_version="1.0"}
      expect(parsed_header_with_tabs).to be_a(Hash(String, String))
      expect(parsed_header_with_tabs.keys.size).to eq 7

      parsed_header_with_spaces_and_tabs = EasyOAuth::Header.parse %{OAuth oauth_consumer_key="abcd",  oauth_nonce="oLKtec51GQy",   oauth_signature="efgh%26mnop",   oauth_signature_method="PLAINTEXT",  oauth_timestamp="1286977095",  oauth_token="ijkl",  oauth_version="1.0"}
      expect(parsed_header_with_spaces_and_tabs).to be_a(Hash(String, String))
      expect(parsed_header_with_spaces_and_tabs.keys.size).to eq 7

      parsed_header_without_spaces = EasyOAuth::Header.parse %{OAuth oauth_consumer_key="abcd",oauth_nonce="oLKtec51GQy",oauth_signature="efgh%26mnop",oauth_signature_method="PLAINTEXT",oauth_timestamp="1286977095",oauth_token="ijkl",oauth_version="1.0"}
      expect(parsed_header_without_spaces).to be_a(Hash(String, String))
      expect(parsed_header_without_spaces.keys.size).to eq 7
    end
  end

  describe "#initialize" do
    let(header) { EasyOAuth::Header.new(:get, "HTTPS://api.TWITTER.com:443/1/statuses/friendships.json?foo=bar#anchor", {} of String => String) }

    it "stringifies and uppercases the request method" do
      expect(header.method).to eq "GET"
    end

    it "downcases the scheme and authority" do
      expect(header.url).to match %r{^https://api\.twitter\.com/}
    end

    it "ignores the query and fragment" do
      expect(header.url).to match %r{/1/statuses/friendships\.json$}
    end
  end

  describe "#valid?" do
    describe "using the HMAC-SHA1 signature method" do
      it "requires consumer and token secrets" do
        secrets = {"consumer_secret" => "CONSUMER_SECRET", "token_secret" => "TOKEN_SECRET"}
        header = EasyOAuth::Header.new(:get, "https://api.twitter.com/1/statuses/friends.json", {} of String => String, secrets)
        parsed_header = EasyOAuth::Header.new(:get, "https://api.twitter.com/1/statuses/friends.json", {} of String => String, header)
        expect(parsed_header.valid?).to be_false
        expect(parsed_header.valid?(secrets)).to be_true
      end
    end

    describe "using the RSA-SHA1 signature method" do
      pending "requires an identical private key"
    end

    describe "using the PLAINTEXT signature method" do
      pending "requires consumer and token secrets"
    end
  end

  describe "#normalized_attributes" do
    let(header) { EasyOAuth::Header.new(:get, "https://api.twitter.com/1/statuses/friends.json", {} of String => String) }

    it "returns a sorted-key, quote-value, and comma-separated list" do
      normalized_attributes = header.normalized_attributes({ "d" => 1, "c" => 2, "b" => 3, "a" => 4 })
      expect(normalized_attributes).to eq %{a="4", b="3", c="2", d="1"}
    end

    it "URI encodes it's values" do
      normalized_attributes = header.normalized_attributes({ 1 => "!", 2 => "@", 3 => "#", 4 => "$" })
      expect(normalized_attributes).to eq %{1="%21", 2="%40", 3="%23", 4="%24"}
    end
  end

  describe "#signed_attributes" do
    it "includes the OAuth signature" do
      header = EasyOAuth::Header.new(:get, "https://api.twitter.com/1/statuses/friends.json", {} of String => String)
      expect(header.signed_attributes.has_key?("oauth_signature")).to be_true
    end
  end

  describe "#attributes" do
    let(header) do
      options = {} of String => String
      EasyOAuth::Header::ATTRIBUTE_KEYS.each { |k| options[k] = k.upcase }
      options["other"] = "OTHER"
      EasyOAuth::Header.new(:get, "https://api.twitter.com/1/statuses/friends.json", {} of String => String, options)
    end

    it "prepends keys with oauth_" do
      header.options["ignore_extra_keys"] = "true"
      header.attributes.keys.each do |key|
        expect(key =~ /^oauth_/).to eq 0
      end
    end

    it "excludes keys not included in the list of valid attributes" do
      header.options["ignore_extra_keys"] = "true"
      expect(header.attributes.has_key?("oauth_other")).to be_false
    end

    it "preserves values for valid keys" do
      header.options["ignore_extra_keys"] = "true"
      expect(header.attributes.size).to eq EasyOAuth::Header::ATTRIBUTE_KEYS.size
      header.attributes.each do |(k, v)|
        expect(k).to eq "oauth_#{v.downcase}"
      end
    end

    it "raises exception for extra keys" do
      expect{header.attributes}.to raise_error(Exception, "EasyOAuth: Found extra option keys not matching ATTRIBUTE_KEYS:\n  [other]")
    end
  end

  describe "#signature" do
    describe "calls the appropriate signature method do" do
      pending "works with HMAC-SHA1" do
        header = EasyOAuth::Header.new(:get, "https://api.twitter.com/1/statuses/friends.json", {} of String => String, { "signature_method" => "HMAC-SHA1" })
      end

      pending "works with RSA-SHA1" do
        header = EasyOAuth::Header.new(:get, "https://api.twitter.com/1/statuses/friends.json", {} of String => String, { "signature_method" => "RSA-SHA1" })
      end

      pending "works with PLAINTEXT" do
        header = EasyOAuth::Header.new(:get, "https://api.twitter.com/1/statuses/friends.json", {} of String => String, { "signature_method" => "PLAINTEXT" })
      end
    end
  end

  describe "#hmac_sha1_signature" do
    it "reproduces a successful Twitter GET" do
      options = {
        "consumer_key" => "8karQBlMg6gFOwcf8kcoYw",
        "consumer_secret" => "3d0vcHyUiiqADpWxolW8nlDIpSWMlyK7YNgc5Qna2M",
        "nonce" => "547fed103e122eecf84c080843eedfe6",
        "signature_method" => "HMAC-SHA1",
        "timestamp" => "1286830180",
        "token" => "201425800-Sv4sTcgoffmHGkTCue0JnURT8vrm4DiFAkeFNDkh",
        "token_secret" => "T5qa1tF57tfDzKmpM89DHsNuhgOY4NT6DlNLsTFcuQ",
      }
      header = EasyOAuth::Header.new(:get, "https://api.twitter.com/1/statuses/friends.json", {} of String => String, options)
      expect(header.to_s).to eq %{OAuth oauth_consumer_key="8karQBlMg6gFOwcf8kcoYw", oauth_nonce="547fed103e122eecf84c080843eedfe6", oauth_signature="i9CT6ahDRAlfGX3hKYf78QzXsaw%3D", oauth_signature_method="HMAC-SHA1", oauth_timestamp="1286830180", oauth_token="201425800-Sv4sTcgoffmHGkTCue0JnURT8vrm4DiFAkeFNDkh", oauth_version="1.0"}
    end

    it "reproduces a successful Twitter POST" do
      options = {
        "consumer_key" => "8karQBlMg6gFOwcf8kcoYw",
        "consumer_secret" => "3d0vcHyUiiqADpWxolW8nlDIpSWMlyK7YNgc5Qna2M",
        "nonce" => "b40a3e0f18590ecdcc0e273f7d7c82f8",
        "signature_method" => "HMAC-SHA1",
        "timestamp" => "1286830181",
        "token" => "201425800-Sv4sTcgoffmHGkTCue0JnURT8vrm4DiFAkeFNDkh",
        "token_secret" => "T5qa1tF57tfDzKmpM89DHsNuhgOY4NT6DlNLsTFcuQ",
      }
      header = EasyOAuth::Header.new(:post, "https://api.twitter.com/1/statuses/update.json", {"status" => "hi, again"}, options)
      expect(header.to_s).to eq %{OAuth oauth_consumer_key="8karQBlMg6gFOwcf8kcoYw", oauth_nonce="b40a3e0f18590ecdcc0e273f7d7c82f8", oauth_signature="mPqSFKejrWWk3ZT9bTQjhO5b2xI%3D", oauth_signature_method="HMAC-SHA1", oauth_timestamp="1286830181", oauth_token="201425800-Sv4sTcgoffmHGkTCue0JnURT8vrm4DiFAkeFNDkh", oauth_version="1.0"}
    end
  end

  describe "#secret" do
    let(header) { EasyOAuth::Header.new(:get, "https://api.twitter.com/1/statuses/friendships.json", {} of String => String) }

    it "combines the consumer and token secrets with an ampersand" do
      header.options.merge!({ "consumer_secret" => "CONSUMER_SECRET", "token_secret" => "TOKEN_SECRET" })
      expect(header.secret).to eq "CONSUMER_SECRET&TOKEN_SECRET"
    end

    it "URI encodes each secret value before combination" do
      header.options.merge!({ "consumer_secret" => "CONSUM#R_SECRET", "token_secret" => "TOKEN_S#CRET" })
      expect(header.secret).to eq "CONSUM%23R_SECRET&TOKEN_S%23CRET"
    end
  end

  describe "#signature_base" do
    let(header) { EasyOAuth::Header.new(:get, "https://api.twitter.com/1/statuses/friendships.json", {} of String => String) }
    let(signature_base) { header.signature_base }

    it "combines the request method, URL, and normalized params using ampersands" do

    end
  end

  describe "#normalized_params" do
    let(header) do
      header = EasyOAuth::Header.new(:get, "https://api.twitter.com/1/statuses/friendships.json", {} of String => String)
      # allow(header).to receive(signature_params).and_return([%w(A 4), %w(B 3), %w(B 2), %w(C 1), ["D[]", "0 "]])
      header
    end
    let(signature_params) { header.signature_params }
    let(normalized_params) { header.normalized_params }

    it "joins key/value pairs with equal signs and ampersands" do
      expect(normalized_params).to be_a(String)
      parts = normalized_params.split("&")
      expect(parts.size).to eq signature_params.size
      pairs = parts.map { |p| p.split("=") }
      pairs.each do |pair|
        expect(pair.size).to eq 2
      end
    end

    describe "#signature_params" do
      let(header) { EasyOAuth::Header.new(:get, "https://api.twitter.com/1/statuses/friendships.json", {} of String => String) }
      let(signature_params) { header.signature_params }

      pending "combines OAuth header attributes, body parameters, and URL parameters into array of key/value pairs"
    end

    describe "#url_params" do
      it "returns an empty array when the URL has no query parameters" do
        header = EasyOAuth::Header.new(:get, "https://api.twitter.com/1/statuses/friendships.json", {} of String => String)
        expect(header.url_params).to eq [] of String
      end

      it "returns an array of key/value pairs for each query parameter" do
        header = EasyOAuth::Header.new(:get, "https://api.twitter.com/1/statuses/friendships.json?test=TEST", {} of String => String)
        expect(header.url_params).to eq [%w(test TEST)]
      end

      it "sorts values for repeated keys" do
        header = EasyOAuth::Header.new(:get, "https://api.twitter.com/1/statuses/friendships.json?test=3&test=1&test=2", {} of String => String)
        expect(header.url_params).to eq [%w(test 1), %w(test 2), %w(test 3)]
      end
    end

    pending "#rsa_sha1_signature"

    describe "#plaintext_signature" do
      it "reproduces a successful OAuth example GET" do
        options = {
          "consumer_key" => "abcd",
          "consumer_secret" => "efgh",
          "nonce" => "oLKtec51GQy",
          "signature_method" => "PLAINTEXT",
          "timestamp" => "1286977095",
          "token" => "ijkl",
          "token_secret" => "mnop"
        }
        header =EasyOAuth::Header.new(:get, "http://host.net/resource?name=value", {"name" => "value"}, options)
        expect(header.to_s).to eq %{OAuth oauth_consumer_key="abcd", oauth_nonce="oLKtec51GQy", oauth_signature="efgh%26mnop", oauth_signature_method="PLAINTEXT", oauth_timestamp="1286977095", oauth_token="ijkl", oauth_version="1.0"}
      end
    end
  end
end
