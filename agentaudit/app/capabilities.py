"""Classify each tool by what it can actually *do*.

Every downstream rule reasons about capabilities rather than tool names, so a
`run_shell` and a `execute_bash_command` are treated identically. Matching is
on word boundaries against the tool name and description together -- a tool
called `send_report_email` and one described as "posts a message to Slack" both
land in NETWORK_SEND.
"""

from __future__ import annotations

import re

from .normalize import Tool

SHELL = "shell_exec"
FILE_READ = "file_read"
FILE_WRITE = "file_write"
NETWORK_FETCH = "network_fetch"
NETWORK_SEND = "network_send"
DB_READ = "db_read"
DB_WRITE = "db_write"
RETRIEVAL = "retrieval"
INBOX_READ = "inbox_read"
USER_DATA = "user_data"
CREDENTIAL = "credential"
PAYMENT = "payment"
DEPLOY = "deploy"
MEMORY_WRITE = "memory_write"

CAPABILITY_LABELS = {
    SHELL: "arbitrary command/code execution",
    FILE_READ: "filesystem read",
    FILE_WRITE: "filesystem write or delete",
    NETWORK_FETCH: "outbound fetch / browsing",
    NETWORK_SEND: "sends data to a third party",
    DB_READ: "database read",
    DB_WRITE: "database write",
    RETRIEVAL: "search / retrieval over a corpus",
    INBOX_READ: "reads messages from other people",
    USER_DATA: "access to private user records",
    CREDENTIAL: "handles credentials or admin actions",
    PAYMENT: "moves money",
    DEPLOY: "changes infrastructure",
    MEMORY_WRITE: "writes to persistent memory",
}

#: capability -> regex of signal words. Kept as raw alternations so the whole
#: taxonomy is readable and auditable in one screen.
_PATTERNS: dict[str, str] = {
    SHELL: r"shell|bash|zsh|\bsh\b|exec|execute_code|run_code|run_command|subprocess|terminal|command_line|\beval\b|interpreter|python_repl|code_interpreter|sandbox_run|system_call",
    FILE_WRITE: r"write_file|writefile|create_file|save_file|edit_file|append_file|delete_file|remove_file|\brm\b|unlink|rmdir|move_file|rename_file|chmod|chown|put_object|upload_file|overwrite|patch_file",
    FILE_READ: r"read_file|readfile|cat_file|open_file|load_file|get_file|list_dir|listdir|list_files|glob|find_file|walk_dir|download_file|get_object|attachment",
    NETWORK_FETCH: r"http_get|http_request|fetch|curl|wget|browse|browser|scrape|crawl|visit_url|open_url|get_url|web_search|url_reader|read_webpage|render_page",
    NETWORK_SEND: r"send_email|sendmail|send_mail|send_message|send_sms|send_text|post_message|slack|discord|telegram|whatsapp|webhook|notify|publish|tweet|post_to|share_to|forward|http_post|upload_to",
    DB_WRITE: r"insert|update_row|update_record|delete_row|delete_record|drop_table|truncate|upsert|write_db|execute_sql|run_sql|migrate|alter_table",
    DB_READ: r"query|select|read_db|fetch_row|get_record|lookup|find_record|sql|database|datastore",
    RETRIEVAL: r"retrieve|retrieval|vector|embedding|semantic_search|knowledge_base|\bkb\b|rag|search|similarity|corpus",
    INBOX_READ: r"read_email|get_email|list_email|inbox|read_messages|get_messages|list_messages|read_thread|get_comments|read_issue|read_pr|list_reviews|get_ticket",
    USER_DATA: r"user_profile|get_user|customer|patient|account_details|personal|profile_data|contact_list|address_book|calendar|health_record|ssn|medical",
    CREDENTIAL: r"api_key|apikey|secret|token|credential|password|passwd|vault|keychain|iam|grant_access|set_permission|create_user|admin|sudo|escalate|rotate_key",
    PAYMENT: r"payment|charge|refund|transfer_funds|transfer_money|invoice|billing|checkout|stripe|payout|wire|purchase|subscription_cancel",
    DEPLOY: r"deploy|kubectl|kubernetes|terraform|ansible|helm|\bssh\b|provision|scale_service|restart_service|docker_run|ci_trigger|release",
    MEMORY_WRITE: r"remember|save_memory|store_memory|update_memory|set_context|persist|save_preference|add_note",
}

def _compile(pattern: str) -> re.Pattern[str]:
    """Compile a signal pattern so multi-word tokens match how people write them.

    Tool *names* use underscores (`read_file`) but descriptions use spaces or
    hyphens ("reads a file", "read-file"), and we match against both in one
    string. Every `_` in the taxonomy therefore becomes "one separator char".
    The leading guard stops `send_email` matching inside `resend_emails`.
    """
    return re.compile(rf"(?<![a-z0-9]){pattern.replace('_', '[_ -]')}", re.IGNORECASE)


_COMPILED = {cap: _compile(pat) for cap, pat in _PATTERNS.items()}

#: Capabilities that describe *doing* something rather than *reading* something.
#: A tool whose name says it reads may not acquire these from its description
#: alone -- otherwise "look up billing history including payment methods" reads
#: as a tool that moves money.
ACTION_CAPABILITIES = {
    SHELL,
    FILE_WRITE,
    DB_WRITE,
    NETWORK_SEND,
    PAYMENT,
    DEPLOY,
    CREDENTIAL,
    MEMORY_WRITE,
}

#: Name prefixes that mark a tool as read-only.
_READ_VERB = re.compile(
    r"^(read|get|list|lookup|look_up|search|find|fetch|view|show|describe|inspect|check|count|export)[_ -]",
    re.IGNORECASE,
)

#: Capabilities that bring attacker-controlled text into the context window.
UNTRUSTED_SOURCES = {NETWORK_FETCH, RETRIEVAL, INBOX_READ, FILE_READ}

#: Capabilities that can move data out of the trust boundary.
EGRESS_SINKS = {NETWORK_SEND, NETWORK_FETCH}

#: Capabilities where a successful injection causes direct, hard-to-undo damage.
DANGEROUS_SINKS = {SHELL, FILE_WRITE, DB_WRITE, PAYMENT, DEPLOY, CREDENTIAL}

#: Capabilities that imply the agent can see data worth stealing.
PRIVATE_DATA = {FILE_READ, DB_READ, INBOX_READ, USER_DATA, RETRIEVAL, CREDENTIAL}

#: Actions nobody should take without a human in the loop.
REQUIRES_CONFIRMATION = {SHELL, FILE_WRITE, DB_WRITE, PAYMENT, DEPLOY, CREDENTIAL, NETWORK_SEND}

#: Parameter names that are effectively "pass me anything" when unconstrained.
FREEFORM_PARAM_NAMES = re.compile(
    r"^(command|cmd|code|script|query|sql|statement|expression|path|file_?path|filename|dir|directory|url|uri|endpoint|body|payload|data|content|input|args|arguments|params|options|prompt|instruction)s?$",
    re.IGNORECASE,
)

#: Parameter names that suggest a raw secret is being handed to the model.
SECRET_PARAM_NAMES = re.compile(
    r"(api_?key|access_?key|secret|token|password|passwd|pwd|credential|private_?key|auth|bearer|session_?id)",
    re.IGNORECASE,
)

#: Parameter names that carry a destination for data leaving the system.
DESTINATION_PARAM_NAMES = re.compile(
    r"^(url|uri|endpoint|host|hostname|domain|webhook|webhook_?url|callback|callback_?url|to|to_?address|recipient|recipients|email|email_?address|channel|phone|number)s?$",
    re.IGNORECASE,
)


def classify(tool: Tool) -> set[str]:
    """Return the capability tags for one tool."""
    text = tool.text
    name = tool.name.lower()
    caps = {cap for cap, rx in _COMPILED.items() if rx.search(text)}

    # A read-named tool only keeps an action capability if its *name* carries
    # that signal, not merely its prose description.
    if _READ_VERB.match(name):
        for action in ACTION_CAPABILITIES & caps:
            if not _COMPILED[action].search(name):
                caps.discard(action)

    # Parameter names are a second signal: a `url` argument means egress even if
    # the tool is called something opaque like `dispatch`.
    for param in tool.params:
        if DESTINATION_PARAM_NAMES.match(param.name):
            if param.name.lower() in ("url", "uri", "endpoint", "webhook", "webhook_url", "callback", "callback_url"):
                caps.add(NETWORK_FETCH)
            else:
                caps.add(NETWORK_SEND)
        if SECRET_PARAM_NAMES.search(param.name):
            caps.add(CREDENTIAL)

    # DB_READ's signals are broad ("query", "lookup"), so only keep it when the
    # tool isn't better explained as a retrieval or fetch tool.
    if DB_READ in caps and not re.search(r"sql|database|datastore|\bdb\b|table|record|row", text):
        caps.discard(DB_READ)

    return caps


def annotate(tools: list[Tool]) -> list[Tool]:
    """Attach capabilities to each tool in place and return the list."""
    for tool in tools:
        tool.capabilities = classify(tool)
    return tools


def tools_with(tools: list[Tool], capabilities: set[str]) -> list[Tool]:
    return [t for t in tools if t.capabilities & capabilities]


def describe(capabilities: set[str]) -> str:
    """Human phrasing for a set of capability tags."""
    labels = [CAPABILITY_LABELS[c] for c in sorted(capabilities) if c in CAPABILITY_LABELS]
    if not labels:
        return "no privileged capability detected"
    if len(labels) == 1:
        return labels[0]
    return ", ".join(labels[:-1]) + " and " + labels[-1]
