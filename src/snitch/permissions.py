"""The exact ``ChatPermissions`` payloads used to mute and to un-mute.

Telegram's ``restrictChatMember`` *replaces* the member's permission set rather
than merging into it, so the mute payload has to be explicit. Sending only the
"can send" fields as ``False`` is not enough on its own: with
``use_independent_chat_permissions=True`` Telegram would otherwise fall back to
its implication rules, and the omitted rights (``can_change_info``,
``can_invite_users``, ``can_pin_messages``, ``can_manage_topics``) can be
revoked implicitly. We therefore set them back to ``True`` so that a mute
cannot silently strip unrelated capabilities.
"""

from __future__ import annotations

from aiogram.types import ChatPermissions

#: Rights that a mute must not touch. Setting them explicitly to ``True`` keeps
#: the restriction narrow: the user can only not post.
_PRESERVED_RIGHTS: dict[str, bool] = {
    "can_change_info": True,
    "can_invite_users": True,
    "can_pin_messages": True,
    "can_manage_topics": True,
}

#: Every "may this user send something" permission, plus link previews and
#: reactions. All of them must be off for a real mute.
_SEND_RIGHTS: tuple[str, ...] = (
    "can_send_messages",
    "can_send_audios",
    "can_send_documents",
    "can_send_photos",
    "can_send_videos",
    "can_send_video_notes",
    "can_send_voice_notes",
    "can_send_polls",
    "can_send_other_messages",
    "can_add_web_page_previews",
    "can_react_to_messages",
)

MUTE_PERMISSIONS: ChatPermissions = ChatPermissions(
    **dict.fromkeys(_SEND_RIGHTS, False),
    **_PRESERVED_RIGHTS,
)

#: Per the Bot API: "Pass True for all boolean parameters to lift restrictions
#: from a user."
UNMUTE_PERMISSIONS: ChatPermissions = ChatPermissions(
    **dict.fromkeys(_SEND_RIGHTS, True),
    **_PRESERVED_RIGHTS,
)

#: Mutes are set with independent permissions so the implication rules above
#: cannot quietly re-grant posting rights.
USE_INDEPENDENT_PERMISSIONS = True
