# easy_oauth

![Travis](https://img.shields.io/travis/watzon/easy_oauth.svg)  ![Github search hit counter](https://img.shields.io/github/search/torvalds/linux/goto.svg) ![license](https://img.shields.io/github/license/mashape/apistatus.svg)

The EasyOAuth shard builds and verifies OAuth headers for use with third party libraries such as [Halite](https://github.com/icyleaf/halite). This library is a port of [laserlemon/simple_oauth](https://github.com/laserlemon/simple_oauth).

## Installation

Add this to your application's `shard.yml`:

```yaml
dependencies:
  easy_oauth:
    github: watzon/easy_oauth
```

## Usage

```crystal
require "halite" # or whatever you want
require "easy_oauth"

options = {
  "consumer_key" => "8karQBlMg6gFOwcf8kcoYw",
  "consumer_secret" => "3d0vcHyUiiqADpWxolW8nlDIpSWMlyK7YNgc5Qna2M",
  "token" => "201425800-Sv4sTcgoffmHGkTCue0JnURT8vrm4DiFAkeFNDkh",
  "token_secret" => "T5qa1tF57tfDzKmpM89DHsNuhgOY4NT6DlNLsTFcuQ"
}

url = https://api.twitter.com/1/statuses/update.json
params = {"status" => "hi, again"}
header = EasyOAuth::Header.new(:post, url, params, options)

response = halite.auth(header).post(url, params: params)
```

## Development

1. Make your changes
2. Run `crystal spec` and make sure you didn't break anything
3. Follow the contributing instructions below
4. Profit

## Contributing

1. Fork it ( https://github.com/watzon/easy_oauth/fork )
2. Create your feature branch (git checkout -b my-new-feature)
3. Commit your changes (git commit -am 'Add some feature')
4. Push to the branch (git push origin my-new-feature)
5. Create a new Pull Request

## Contributors

- [watzon](https://github.com/watzon) Chris Watson - creator, maintainer
