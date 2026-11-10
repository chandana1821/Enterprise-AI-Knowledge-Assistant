from pydantic_settings import BaseSettings, SettingsConfigDict
from uuid import UUID
import hashlib

class Settings(BaseSettings):
    database_url: str = "postgresql+asyncpg://knowbase:knowbase@localhost:5432/knowbase"
    jwt_secret: str = "development-only-change-me"
    access_token_minutes: int = 60
    freshness_sla_minutes: int = 1440
    gemini_api_key: str = ""
    gemini_model: str = "gemini-3.5-flash-lite"
    gemini_embedding_model: str = "gemini-embedding-001"
    gemini_embedding_batch_size: int = 8
    gemini_retry_seconds: int = 90
    upload_dir: str = "./uploads"
    similarity_threshold: float = 0.45
    workspace_id: UUID = UUID("11111111-1111-4111-8111-111111111111")
    workspace_name: str = "Northstar Inc."
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

settings = Settings()

def embedding_space_fingerprint() -> str:
    """Identity for vectors that may participate in the same similarity search."""
    value="|".join(("gemini",settings.gemini_embedding_model,"1536"))
    return hashlib.sha256(value.encode("utf-8")).hexdigest()
