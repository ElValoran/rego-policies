package istio.authz

import rego.v1

default allow := false

# allow if {
# 	input.parsed_path[0] == "graphql"
# 	input.attributes.request.http.method == "POST"
# 	input.parsed_body.query == "query{\r\n    getProducts{\r\n        _id\r\n        name\r\n        description\r\n    }\r\n}"
# }

# allow if {
#     input.parsed_path[0] == "graphql"
#     input.attributes.request.http.method == "POST"
# }

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
    graphql_is_valid
    is_allowed_query
}

allow if {
    graphql_is_valid
    is_allowed_mutation
}

graphql_is_valid if {
    input.parsed_path[0] == "graphql"
    input.attributes.request.http.method == "POST"
    graphql.schema_is_valid(schema) == true
    graphql.is_valid(input.parsed_body.query, schema) == true

    print(request)
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
}
