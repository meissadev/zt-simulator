# authz_test.rego
#
# Tests unitaires de la politique d'autorisation.
# Exécution : opa test pdp/policies/ -v

package authz

import rego.v1

test_allow_engineer_get if {
	allow with input as {
		"subject": {"auth_method": "jwt", "role": "engineer"},
		"resource": "/api/data",
		"method": "GET",
	}
}

test_allow_engineer_post if {
	allow with input as {
		"subject": {"auth_method": "jwt", "role": "engineer"},
		"resource": "/api/data",
		"method": "POST",
	}
}

test_allow_auditor_get if {
	allow with input as {
		"subject": {"auth_method": "jwt", "role": "auditor"},
		"resource": "/api/data",
		"method": "GET",
	}
}

test_deny_auditor_post if {
	not allow with input as {
		"subject": {"auth_method": "jwt", "role": "auditor"},
		"resource": "/api/data",
		"method": "POST",
	}
}

test_allow_mtls_get if {
	allow with input as {
		"subject": {"auth_method": "mtls", "service_id": "pep"},
		"resource": "/api/data",
		"method": "GET",
	}
}

test_deny_mtls_post if {
	not allow with input as {
		"subject": {"auth_method": "mtls", "service_id": "pep"},
		"resource": "/api/data",
		"method": "POST",
	}
}

test_deny_unknown_role if {
	not allow with input as {
		"subject": {"auth_method": "jwt", "role": "guest"},
		"resource": "/api/data",
		"method": "GET",
	}
}

test_deny_no_resource_match if {
	not allow with input as {
		"subject": {"auth_method": "jwt", "role": "engineer"},
		"resource": "/admin/settings",
		"method": "GET",
	}
}
