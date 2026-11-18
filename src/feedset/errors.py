"""Fixed errors. The text never includes a secret value."""


class FeedsetError(Exception):
    """A generation did not publish. The previous files stay."""


class Busy(FeedsetError):
    """Another build holds the lock."""
