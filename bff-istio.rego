package istio.authz

import rego.v1

default allow := true

allow if {
	input.parsed_path[0] == "graphql"
	input.attributes.request.http.method == "POST"
	input.parsed_body.query == "query{\r\n    getProducts{\r\n        _id\r\n        name\r\n        description\r\n    }\r\n}"
}
