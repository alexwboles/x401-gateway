"""x401 -- free, self-hosted x401 (v0.2.0) agent identity gateway core library."""

from .codec import CodecError, decode_payload, emit_header, encode_payload, parse_header
from .html import embed_html
from .jws import (
    JWSError,
    generate_ed25519_keypair,
    generate_p256_keypair,
    jwk_public,
    key_from_jwk_public,
    parse_x5c,
    sign,
    verify,
)
from .mandate import (
    MANDATE_TYPE,
    MandateError,
    build_mandate,
    canonical as mandate_canonical,
    sign_mandate,
    verify_mandate,
)
from .nonce import NonceCache, NonceError
from .oauth import (
    OAuthError,
    RESULT_ARTIFACT_TYPE,
    TOKEN_EXCHANGE_GRANT,
    build_token_request,
    issue_access_token,
    verify_access_token,
)
from .request import RequestError, build_proof_request, parse_proof_request
from .response import ResponseError, dereference, parse_proof_response
from .result import ERROR_TOKENS, ResultError, make_result, parse_result
from .trust import TrustList, default_self_issued_only

__all__ = [
    # codec
    "CodecError",
    "encode_payload",
    "decode_payload",
    "parse_header",
    "emit_header",
    # jws
    "JWSError",
    "sign",
    "verify",
    "generate_ed25519_keypair",
    "generate_p256_keypair",
    "jwk_public",
    "key_from_jwk_public",
    "parse_x5c",
    # request
    "RequestError",
    "build_proof_request",
    "parse_proof_request",
    # response
    "ResponseError",
    "parse_proof_response",
    "dereference",
    # result
    "ResultError",
    "ERROR_TOKENS",
    "make_result",
    "parse_result",
    # trust
    "TrustList",
    "default_self_issued_only",
    # nonce
    "NonceError",
    "NonceCache",
    # oauth
    "OAuthError",
    "TOKEN_EXCHANGE_GRANT",
    "RESULT_ARTIFACT_TYPE",
    "build_token_request",
    "issue_access_token",
    "verify_access_token",
    # mandate (gateway extension -- NOT spec)
    "MandateError",
    "MANDATE_TYPE",
    "mandate_canonical",
    "build_mandate",
    "sign_mandate",
    "verify_mandate",
    # html
    "embed_html",
]

__version__ = "0.1.0"
