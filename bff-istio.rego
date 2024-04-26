package istio.authz

import rego.v1
import input.attributes.request.http as http_request
import input.parsed_path

default allow := true

allow {
    parsed_path[0] == "graphql"
    http_request.method == "POST"
    input.parsed_body.query == "getProduct(_id: ID): Product"
}