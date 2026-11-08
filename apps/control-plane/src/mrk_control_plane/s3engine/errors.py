# ruff: noqa: E501 - long AWS error messages
"""S3 error model (docs/30 §1.8)."""

from __future__ import annotations

_DEFAULTS: dict[str, tuple[int, str]] = {
    "AccessDenied": (403, "Access Denied"),
    "AccountProblem": (403, "There is a problem with your account."),
    "AuthorizationHeaderMalformed": (400, "The authorization header is malformed."),
    "AuthorizationQueryParametersError": (
        400,
        "Error parsing the query-string authentication parameters.",
    ),
    "BadDigest": (
        400,
        "The Content-MD5 or checksum value that you specified did not match what the server received.",
    ),
    "BucketAlreadyExists": (409, "The requested bucket name is not available."),
    "BucketAlreadyOwnedByYou": (
        409,
        "Your previous request to create the named bucket succeeded and you already own it.",
    ),
    "BucketNotEmpty": (409, "The bucket that you tried to delete is not empty."),
    "ConditionalRequestConflict": (409, "A conflicting operation occurred."),
    "EntityTooLarge": (400, "Your proposed upload exceeds the maximum allowed size."),
    "EntityTooSmall": (
        400,
        "Your proposed upload is smaller than the minimum allowed object size.",
    ),
    "IncompleteBody": (
        400,
        "You did not provide the number of bytes specified by the Content-Length HTTP header.",
    ),
    "InternalError": (500, "We encountered an internal error. Please try again."),
    "InvalidAccessKeyId": (
        403,
        "The AWS Access Key Id you provided does not exist in our records.",
    ),
    "InvalidArgument": (400, "Invalid Argument"),
    "InvalidBucketName": (400, "The specified bucket is not valid."),
    "InvalidChunkSizeError": (
        403,
        "Only the last chunk is allowed to have a size less than 8192 bytes",
    ),
    "InvalidDigest": (400, "The Content-MD5 you specified is not valid."),
    "InvalidPart": (
        400,
        "One or more of the specified parts could not be found. The part might not have been uploaded, or the specified entity tag might not have matched the part's entity tag.",
    ),
    "InvalidPartOrder": (
        400,
        "The list of parts was not in ascending order. The parts list must be specified in order by part number.",
    ),
    "InvalidRange": (416, "The requested range is not satisfiable"),
    "InvalidRequest": (400, "Invalid Request"),
    "InvalidSignature": (
        403,
        "The request signature we calculated does not match the signature you provided.",
    ),
    "InvalidStorageClass": (400, "The storage class you specified is not valid."),
    "KeyTooLongError": (400, "Your key is too long."),
    "MalformedXML": (
        400,
        "The XML you provided was not well-formed or did not validate against our published schema.",
    ),
    "MetadataTooLarge": (400, "Your metadata headers exceed the maximum allowed metadata size."),
    "MethodNotAllowed": (405, "The specified method is not allowed against this resource."),
    "MissingContentLength": (411, "You must provide the Content-Length HTTP header."),
    "MissingSecurityHeader": (400, "Your request is missing a required header."),
    "NoSuchBucket": (404, "The specified bucket does not exist."),
    "NoSuchKey": (404, "The specified key does not exist."),
    "NoSuchUpload": (
        404,
        "The specified multipart upload does not exist. The upload ID might be invalid, or the multipart upload might have been aborted or completed.",
    ),
    "NoSuchVersion": (404, "The specified version does not exist."),
    "NotImplemented": (501, "A header you provided implies functionality that is not implemented."),
    "PreconditionFailed": (412, "At least one of the preconditions you specified did not hold."),
    "QuotaExceeded": (403, "The bucket quota would be exceeded by this request."),
    "RequestHeaderSectionTooLarge": (
        400,
        "Your request header section exceeds the maximum allowed size.",
    ),
    "RequestTimeout": (
        400,
        "Your socket connection to the server was not read from or written to within the timeout period.",
    ),
    "RequestTimeTooSkewed": (
        403,
        "The difference between the request time and the current time is too large.",
    ),
    "ServerSideEncryptionConfigurationNotFoundError": (
        404,
        "The server side encryption configuration was not found",
    ),
    "ServiceUnavailable": (503, "The S3 service is disabled or unavailable."),
    "SignatureDoesNotMatch": (
        403,
        "The request signature we calculated does not match the signature you provided. Check your key and signing method.",
    ),
    "SlowDown": (503, "Please reduce your request rate."),
    "XAmzContentSHA256Mismatch": (
        400,
        "The provided 'x-amz-content-sha256' header does not match what was computed.",
    ),
    "NoSuchBucketPolicy": (404, "The bucket policy does not exist"),
    "NoSuchCORSConfiguration": (404, "The CORS configuration does not exist"),
    "NoSuchLifecycleConfiguration": (404, "The lifecycle configuration does not exist"),
    "NoSuchTagSet": (404, "The TagSet does not exist"),
    "NoSuchWebsiteConfiguration": (
        404,
        "The specified bucket does not have a website configuration",
    ),
    "InsufficientStorage": (507, "Insufficient storage space."),
}


class S3Error(Exception):
    """An S3 protocol error, rendered as ``<Error>`` XML (no body for HEAD)."""

    def __init__(
        self,
        code: str,
        message: str | None = None,
        status: int | None = None,
        *,
        headers: dict[str, str] | None = None,
        **details: str,
    ) -> None:
        default_status, default_message = _DEFAULTS.get(code, (400, code))
        self.code = code
        self.message = message or default_message
        self.status = status or default_status
        self.details = {key: str(value) for key, value in details.items() if value is not None}
        self.headers = headers or {}
        super().__init__(f"{code}: {self.message}")
