class DbError(Exception):
    """Every failure the database layer reports. `slug` is stable and machine-read,
    `message` says what happened, `hint` (possibly None) says what to do."""

    def __init__(self, slug: str, message: str, hint: str | None = None):
        super().__init__(message)
        self.slug = slug
        self.message = message
        self.hint = hint

    def __repr__(self) -> str:
        return f"DbError({self.slug!r}, {self.message!r}, {self.hint!r})"
