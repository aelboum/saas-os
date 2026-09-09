"""`core/notifications` -- generic notification dispatch pipeline
(docs/IMPLEMENTATION-ROADMAP.md Phase 4.4; docs/ARCHITECTURE.md section 4:
"Notification dispatch pipeline (templates are Product-supplied via the
contract)").

Owns:
- the tenant-owned `Notification` entity (`core.notifications`,
  RLS-protected) -- one dispatched (or attempted) notification;
- `dispatch_notification()`, the entrypoint that enqueues delivery
  through `infra.jobs`;
- `NOTIFICATION_JOB_FUNCTIONS`, the registered `infra.jobs` handler a
  worker process registers to actually perform dispatch;
- `get_notification`/`list_notifications`.

Two channels are implemented: `"in_app"` (docs/IMPLEMENTATION-ROADMAP.md
Phase 4.4's own Acceptance Criteria only requires "at least one channel
end-to-end") and, since P1.12, `"email"` (via `core.email.send_email()`).
`"sms"`/`"push"` remain illustrative future channels named by the
roadmap's Objective, not built yet -- adding one later means a new
dispatch branch and provider adapter in `core/notifications/service.py`,
never a schema change, exactly as `"email"` itself just demonstrated.

Does NOT own: template/content authoring (deferred to the future Product
Contract, `docs/ARCHITECTURE.md` section 9), retry/backoff/dead-letter
execution bookkeeping (`infra/jobs`, reused here, never reimplemented --
docs/DATA-ARCHITECTURE.md section 5), or any HTTP/API surface (Phase 8).
"""

from core.notifications.errors import (
    InvalidNotificationChannelError,
    NotificationDispatchError,
    NotificationNotFoundError,
)
from core.notifications.models import Notification
from core.notifications.service import (
    NOTIFICATION_JOB_FUNCTIONS,
    dispatch_notification,
    get_notification,
    list_notifications,
)

__all__ = [
    "Notification",
    "dispatch_notification",
    "get_notification",
    "list_notifications",
    "NOTIFICATION_JOB_FUNCTIONS",
    "InvalidNotificationChannelError",
    "NotificationNotFoundError",
    "NotificationDispatchError",
]
