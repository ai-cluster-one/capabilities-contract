class DbError(Exception):
    """Every failure the database layer reports. `slug` is stable and machine-read,
    `message` says what happened, `hint` (possibly None) says what to do.
    `dials_again_at` is the `time.monotonic()` moment from which a transaction
    connect to the same address dials the store again, on a `store_unreachable`
    refusal that left the address paused; None when the next connect dials."""

    def __init__(self, slug: str, message: str, hint: str | None = None, *,
                 dials_again_at: float | None = None):
        super().__init__(message)
        self.slug = slug
        self.message = message
        self.hint = hint
        self.dials_again_at = dials_again_at

    def __repr__(self) -> str:
        return f"DbError({self.slug!r}, {self.message!r}, {self.hint!r})"
