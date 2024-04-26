# package istio.authz

# import rego.v1

# default allow := false

# allow if {
#     input.parsed_path[0] == "api"
#     input.parsed_path[1] == "v1"
#     input.parsed_path[2] == "productOrders"
#     input.parsed_path[3] == "customer"
#     input.attributes.request.http.method == "POST"

#     ...
# }

# allow if {
#     input.parsed_path[0] == "api"
#     input.parsed_path[1] == "v1"
#     input.parsed_path[2] == "productOrders"
#     input.attributes.request.http.method == "POST"

#     ...
# }