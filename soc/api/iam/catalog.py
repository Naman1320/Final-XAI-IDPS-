"""The permission catalog: a code constant, never stored in the database.

Roles, groups and policies reference permissions by name. A name that is not in the catalog is
refused when it is saved and ignored when it is read (a catalog entry removed in a later release
simply stops granting anything).
"""

from fnmatch import fnmatchcase

# (group key, title, ((permission, description), ...))
_GROUPS: tuple[tuple[str, str, tuple[tuple[str, str], ...]], ...] = (
    ("cloud", "Cloud", (
        ("cloud.view", "View cloud instances, storage, network and alerts"),
        ("cloud.instances.write", "Create, change and delete cloud instances"),
        ("cloud.storage.write", "Create, change and delete cloud storage"),
        ("cloud.network.write", "Change cloud network rules"),
        ("cloud.alerts.manage", "Triage and manage cloud alerts"),
    )),
    ("users", "Users", (
        ("iam.users.view", "View users, their roles, groups and effective permissions"),
        ("iam.users.write", "Create and change users; activate and deactivate them"),
        ("iam.users.delete", "Delete users"),
    )),
    ("roles", "Roles", (
        ("iam.roles.view", "View roles and the permission catalog"),
        ("iam.roles.write", "Create, change and delete custom roles"),
    )),
    ("groups", "Groups", (
        ("iam.groups.view", "View groups, their members and roles"),
        ("iam.groups.write", "Create, change and delete groups; set members and roles"),
    )),
    ("policies", "Policies", (
        ("iam.policies.view", "View allow and deny policies and where they are attached"),
        ("iam.policies.write", "Create, change and delete policies; attach them"),
    )),
    ("monitoring", "Monitoring", (
        ("iam.audit.view", "View the audit log"),
        ("iam.logins.view", "View the login history"),
    )),
)

CATALOG = tuple(
    {"key": key, "title": title,
     "permissions": [{"name": n, "description": d} for n, d in perms]}
    for key, title, perms in _GROUPS)
ALL_PERMISSIONS: frozenset[str] = frozenset(n for _, _, perms in _GROUPS for n, _ in perms)
DESCRIPTIONS: dict[str, str] = {n: d for _, _, perms in _GROUPS for n, d in perms}


def expand(patterns) -> set[str]:
    """The catalog permissions matched by exact names or `*` patterns such as "cloud.*"."""
    return {p for p in ALL_PERMISSIONS if any(fnmatchcase(p, pat) for pat in patterns)}


def valid_pattern(pattern: str) -> bool:
    """A permission pattern: lower-case letters, digits, `_`, `.` and `*`, matching at least one
    catalog permission (so a typo is an error rather than a policy that does nothing)."""
    return (0 < len(pattern) <= 64 and all(c.islower() or c.isdigit() or c in "_.*"
                                           for c in pattern) and bool(expand([pattern])))
