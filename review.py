"""Where a model reviewer would slot in — deliberately a placeholder.

The scanner above is the cheap filter. The expensive step is a human (or
a model) reading a flagged snippet in context and deciding whether it's
actually exploitable. This module just drafts that review prompt; it
makes no API call and needs no key. Wire your own model client into
review_with_model() when you want the second stage — the scanner's job
is to make sure the model only ever sees the suspicious 1% of a repo,
not the whole thing.
"""

from scanner import Finding


def draft_review_prompt(filepath, finding: Finding):
    return (
        "You are reviewing a Python security finding. Decide whether it is "
        "genuinely exploitable in context, or a false positive, and explain "
        "why in one paragraph.\n\n"
        f"File: {filepath}\n"
        f"Finding: {finding.rule} [{finding.severity}] line {finding.line}\n"
        f"Reason: {finding.message}\n"
        f"Code: {finding.snippet}\n"
    )


def review_with_model(filepath, finding: Finding):
    """Not implemented on purpose — plug in your model client here."""
    raise NotImplementedError(
        "no model wired up. Use draft_review_prompt() to see what would be sent."
    )
