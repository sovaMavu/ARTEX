"""Allow ``python -m runner`` to start the MCP server."""

from .server import main

if __name__ == "__main__":  # pragma: no cover
    main()
