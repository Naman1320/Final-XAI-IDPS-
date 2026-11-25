"""Cloud side of the IDPS: VPC Flow Logs in, network ACL deny rules out.

Nothing here imports boto3 at module level; it is an optional dependency
(`pip install -e ".[cloud]"`) and is only imported when a client is created.
"""
