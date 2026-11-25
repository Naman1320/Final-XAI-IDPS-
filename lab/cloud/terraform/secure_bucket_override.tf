# Applied only by lab/cloud/tf.sh (copied into the work folder's modules/secure_bucket/); infra/
# itself is unchanged. Moto evaluates bucket policies without their Condition blocks (its own
# docs: "Conditions are not taken into account"), so the real design's DenyInsecureTransport
# statement (Deny s3:* when aws:SecureTransport is false) would deny EVERY request, TLS or not,
# and nothing could ever read or write the emulated buckets (found in C3).
# Here the statement keeps its shape and condition but names an action nobody calls, so in the
# emulator it does nothing. On real AWS the unmodified statement in infra/ applies.
data "aws_iam_policy_document" "tls_only" {
  statement {
    sid       = "DenyInsecureTransport"
    effect    = "Deny"
    actions   = ["s3:BypassGovernanceRetention"]
    resources = [aws_s3_bucket.this.arn, "${aws_s3_bucket.this.arn}/*"]

    principals {
      type        = "*"
      identifiers = ["*"]
    }

    condition {
      test     = "Bool"
      variable = "aws:SecureTransport"
      values   = ["false"]
    }
  }
}
