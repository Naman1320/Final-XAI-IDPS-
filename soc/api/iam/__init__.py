"""IAM / RBAC: roles, groups, policies, effective permissions and login history.

Kept free of imports so that soc.api.auth can import the small modules (engine, history) without
a cycle; the routes are assembled in soc.api.iam.router.
"""
