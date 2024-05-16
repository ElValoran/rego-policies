package istio.authz

import rego.v1

default allow := false

schema := `
type Product {
    _id: ID
    name: String
    price: Float
    description: String
}

type Query {
    getProduct(_id: ID): Product
    getProducts: [Product]
}

type Mutation {
    createProduct(productInput: ProductInput!): Product
    login(basicAuthInput: BasicAuthInput!): String
    addProductToCart(shoppingCartInput: ShoppingCartInput!): String
    deleteShoppingCart(customerId: ID!): String
    createProductOrder(shippingAddress: String!): String
}

input ShoppingCartInput {
    productId: ID!,
    quantity: Int
}

input ProductInput {
    name: String
    price: Float
    description: String
}

input BasicAuthInput {
    email: String!
    password: String!
}
`
request := graphql.parse(input.parsed_body.query, schema)
op := request[0].Operations[_]
selection := op.SelectionSet[_]

allow if {
    input.attributes.destination.principal == "spiffe://cluster.local/ns/default/sa/backend-for-frontend-sa"
    input.attributes.request.http.headers.path == "/graphql"
    graphql_is_valid
    is_allowed_mutation_or_query
}

graphql_is_valid if {
    input.parsed_path[0] == "graphql"
    input.attributes.request.http.method == "POST"
    graphql.schema_is_valid(schema) == true
    graphql.is_valid(input.parsed_body.query, schema) == true

    print(request)
}

is_allowed_mutation_or_query if {
    is_allowed_query
}

allow if {
    is_allowed_mutation
}

is_allowed_query if {
    op.Operation == "query"
    is_allowed_query_operation
}

is_allowed_query_operation if {
    selection.Alias == "getProducts"
}

is_allowed_mutation if {
    op.Operation == "mutation"
    is_allowed_mutation_operation
}

is_allowed_mutation_operation if {
    selection.Alias == "login"
}

is_allowed_mutation_operation if {
    selection.Alias == "addProductToCart"
    claims.role == "customer"
}

is_allowed_mutation_operation if {
    selection.Alias == "createProduct"
    claims.role == "product-manager"
}

claims := payload if {
	# Verify the signature on the Bearer token. In this example the secret is
	# hardcoded into the policy however it could also be loaded via data or
	# an environment variable. Environment variables can be accessed using
	# the `opa.runtime()` built-in function.
	io.jwt.verify_hs256(bearer_token, `-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAwV2CrH3goELMrWt/J2mA
y/sVko9WjyrzbRDi0WOHZFAOuqYt5Qro30OJtZ3ejrKwW9UdG76c1RTu8WjkqWHW
TedyfaSnip+op/vqWjze1EiR6+i6zocALocNQokQe7Ar7FWSPzhTa6wCX3edSeAC
54C7VndoBsgUYJc2+JRznSzH54j7QfUMayQNg6jsnf7m+BFtYqHlROCTGe/ca/78
0ud0tsLalpaCsB83dCcJi8HoNlVE6+Yv1lCEUlZc/5lLXFnBdnXfhLzlItPgR4Ql
GIra90wWDfArKcinPP+9L4gYjTCSdSTfmrH8ooMWeikNYfHgrK9odgWwuNw2Jo2i
MwIDAQAB
-----END PUBLIC KEY-----`)

	# This statement invokes the built-in function `io.jwt.decode` passing the
	# parsed bearer_token as a parameter. The `io.jwt.decode` function returns an
	# array:
	#
	#	[header, payload, signature]
	#
	# In Rego, you can pattern match values using the `=` and `:=` operators. This
	# example pattern matches on the result to obtain the JWT payload.
	[_, payload, _] := io.jwt.decode(bearer_token)
}

# Source: https://play.openpolicyagent.org/
bearer_token := t if {
	# Bearer tokens are contained inside of the HTTP Authorization header. This rule
	# parses the header and extracts the Bearer token value. If no Bearer token is
	# provided, the `bearer_token` value is undefined.
	v := input.attributes.request.http.headers.authorization
	startswith(v, "Bearer ")
	t := substring(v, count("Bearer "), -1)
}