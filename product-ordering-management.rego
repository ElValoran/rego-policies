package product_ordering_management.authz

import rego.v1

filtered_product_orders := [] if {
  not input.claims.role == "CUSTOMER_SUPPORT"
  not input.claims.role == "CUSTOMER"
}

filtered_product_orders := [product_order | 
  product_order := input.product_orders[_]
  product_order.support.requested == true
  product_order.support.id == input.claims.id
] if {
  input.claims.role == "CUSTOMER_SUPPORT"
}

filtered_product_orders := [product_order | 
  product_order := input.product_orders[_]
  product_order.customer.id == input.claims.id
] if {
  input.claims.role == "CUSTOMER"
}