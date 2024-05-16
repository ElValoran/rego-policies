# package bff.authz

# import rego.v1

# default allow := false

# token := input.token

# claims := payload if {
# 	# Verify the signature on the Bearer token. In this example the secret is
# 	# hardcoded into the policy however it could also be loaded via data or
# 	# an environment variable. Environment variables can be accessed using
# 	# the `opa.runtime()` built-in function.
# 	io.jwt.verify_rs256(token, `-----BEGIN PUBLIC KEY-----
# MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAwV2CrH3goELMrWt/J2mA
# y/sVko9WjyrzbRDi0WOHZFAOuqYt5Qro30OJtZ3ejrKwW9UdG76c1RTu8WjkqWHW
# TedyfaSnip+op/vqWjze1EiR6+i6zocALocNQokQe7Ar7FWSPzhTa6wCX3edSeAC
# 54C7VndoBsgUYJc2+JRznSzH54j7QfUMayQNg6jsnf7m+BFtYqHlROCTGe/ca/78
# 0ud0tsLalpaCsB83dCcJi8HoNlVE6+Yv1lCEUlZc/5lLXFnBdnXfhLzlItPgR4Ql
# GIra90wWDfArKcinPP+9L4gYjTCSdSTfmrH8ooMWeikNYfHgrK9odgWwuNw2Jo2i
# MwIDAQAB
# -----END PUBLIC KEY-----`)

# 	# This statement invokes the built-in function `io.jwt.decode` passing the
# 	# parsed bearer_token as a parameter. The `io.jwt.decode` function returns an
# 	# array:
# 	#
# 	#	[header, payload, signature]
# 	#
# 	# In Rego, you can pattern match values using the `=` and `:=` operators. This
# 	# example pattern matches on the result to obtain the JWT payload.
# 	[_, payload, _] := io.jwt.decode(token)
# }

# allow if {
#     claims.role == "product-manager"
#     input.method == "POST"
#     input.path == "/productOffers"
# }

# allow if {
# 	print(claims)
# 	claims.role == "customer"
#     input.method == "POST"
#     input.path == "/shoppingCarts"
# }