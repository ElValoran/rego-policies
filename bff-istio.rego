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

allow if {
    input.parsed_path[0] == "graphql"
    input.attributes.request.http.method == "POST"
    graphql.schema_is_valid(schema) == true

    parsed := graphql.parse_and_verify(input.query, schema)
    is_valid = parsed[0]
    is_valid

    # graphql.is_valid(input.parsed_body.query, schema) == true

    query := parsed[1]
    # request := graphql.parse(input.parsed_body.query, schema)
    print(query)
    op := query.Operations[_]
    op.Operation == "query"
}

