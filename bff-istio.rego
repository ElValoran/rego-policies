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

allow if {
    input.parsed_path[0] == "graphql"
    input.attributes.request.http.method == "POST"
    graphql.schema_is_valid(schema) == true
    graphql.is_valid(input.parsed_body.query, schema) == true

    # request := graphql.parse(input.parsed_body.query, schema)
    op := request.Operations[_]
    op.Operation == "query"
}

