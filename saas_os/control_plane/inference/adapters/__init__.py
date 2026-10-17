"""INTERNAL provider protocol adapters (AI-B, AI-G; contracts document section 2).

Not a supported API; see `saas_os.control_plane.inference`. Only
`saas_os.control_plane.inference` may import this package (import-linter).
"""

from saas_os.control_plane.inference.adapters.anthropic_messages import AnthropicMessagesAdapter
from saas_os.control_plane.inference.adapters.base import (
    AdapterMessage,
    AdapterRequest,
    AdapterResult,
    AdapterUsage,
    Capability,
    EgressClient,
    FinishReason,
    OpaqueCredential,
    ProviderAdapter,
    ResolvedTarget,
)
from saas_os.control_plane.inference.adapters.errors import (
    AdapterError,
    ErrorCategory,
    error_from_egress,
)
from saas_os.control_plane.inference.adapters.fake import FakeAdapter, FakeCall
from saas_os.control_plane.inference.adapters.openai_compatible import OpenAICompatibleAdapter

__all__ = [
    "AdapterError",
    "AdapterMessage",
    "AdapterRequest",
    "AdapterResult",
    "AdapterUsage",
    "AnthropicMessagesAdapter",
    "Capability",
    "EgressClient",
    "ErrorCategory",
    "FakeAdapter",
    "FakeCall",
    "FinishReason",
    "OpaqueCredential",
    "OpenAICompatibleAdapter",
    "ProviderAdapter",
    "ResolvedTarget",
    "error_from_egress",
]
