import argparse
import sys

import uvicorn


def main() -> None:
    parser = argparse.ArgumentParser(description="Run a Schrödinger Package service")
    parser.add_argument("role", choices=("portal", "inspector", "runtime"))
    role = parser.parse_args().role

    if role == "portal":
        from schrodinger.portal.app import create_app

        app = create_app()
        port = 8080
    elif role == "inspector":
        from schrodinger.inspector.app import app

        port = 8081
    else:
        if sys.platform == "linux":
            from schrodinger.runtime.limits import protect_runtime_parent

            protect_runtime_parent()
        from schrodinger.runtime.app import app

        port = 8082

    uvicorn.run(app, host="0.0.0.0", port=port)


if __name__ == "__main__":
    main()
