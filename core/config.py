import os
import sys
from pathlib import Path
from dotenv import load_dotenv

BASE_DIR = Path(__file__).resolve().parent.parent
load_dotenv(BASE_DIR / ".env")
SERVICES_DIR = BASE_DIR / "services"
SHARED_DIR = BASE_DIR / "shared"

# ------------------------------------------------------------------------------
# Application Environment Mode ('development' or 'production')
# ------------------------------------------------------------------------------
def get_env_mode() -> str:
    raw = (os.getenv("OASIS_ENV") or os.getenv("APP_ENV") or os.getenv("ENVIRONMENT") or "").strip().lower()
    if raw in ("development", "dev", "local", "staging", "test", "testing"):
        return "development"
    if raw in ("production", "prod", "live"):
        return "production"
    if os.getenv("OASIS_DEV_MODE", "").strip().lower() in ("1", "true", "yes", "on"):
        return "development"
    return "production"

OASIS_ENV = get_env_mode()
IS_PRODUCTION = (OASIS_ENV == "production")
IS_DEVELOPMENT = (OASIS_ENV == "development")

# Gateway Configuration
GATEWAY_PORT = int(os.getenv("OASIS_PORT", 5050))

# Platform Metadata
IS_WINDOWS = sys.platform.startswith("win")
IS_LINUX = sys.platform.startswith("linux")
IS_DARWIN = sys.platform.startswith("darwin")

APP_NAME = "Oasis Reconnaissance & Intelligence Suite"
APP_VERSION = "1.6.0"
ANALYST_NAME = "User"
ANALYST_ROLE = "INTELLIGENCE ANALYST"
