require "uri"
require "spec2-mocks"
require "../src/easy_oauth"

include Spec2::GlobalDSL

Spec2.doc

Mocks.create_mock EasyOAuth::Header do
  mock method
  mock url
  mock normalized_params
  mock signature_params
end
