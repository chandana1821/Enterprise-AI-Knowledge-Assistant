import enum, uuid
from datetime import datetime, timezone
from sqlalchemy import String, Boolean, Integer, BigInteger, DateTime, ForeignKey, Text, Enum, Float, JSON, UniqueConstraint
from sqlalchemy.dialects.postgresql import UUID, JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship
from pgvector.sqlalchemy import Vector
from .db import Base
from .config import settings

def now(): return datetime.now(timezone.utc)
class UserRole(str,enum.Enum): ADMIN="ADMIN"; USER="USER"
class SystemPermission(str,enum.Enum): ADMIN="ADMIN"; EMPLOYEE="EMPLOYEE"
class Department(str,enum.Enum): ENGINEERING="Engineering"; HR="HR"; FINANCE="Finance"; EXECUTIVE="Executive"; SECURITY="Security"; PEOPLE="People"
class Freshness(str,enum.Enum): FRESH="FRESH"; STALE="STALE"; QUEUED="QUEUED"; PROCESSING="PROCESSING"; RETRYING="RETRYING"; FAILED="FAILED"; DELETED="DELETED"
class Ingestion(str,enum.Enum): PENDING="PENDING"; INDEXED="INDEXED"; FAILED="FAILED"
class DocumentAccessType(str,enum.Enum): ALL_EMPLOYEES="ALL_EMPLOYEES"; ADMIN_ONLY="ADMIN_ONLY"; SPECIFIC_EMPLOYEE_ROLES="SPECIFIC_EMPLOYEE_ROLES"; SPECIFIC_USERS="SPECIFIC_USERS"
class Workspace(Base):
    __tablename__="workspaces"
    id: Mapped[uuid.UUID]=mapped_column(UUID(as_uuid=True),primary_key=True,default=settings.workspace_id)
    name: Mapped[str]=mapped_column(String(200),default=settings.workspace_name)
    created_at: Mapped[datetime]=mapped_column(DateTime(timezone=True),default=now)
class EmployeeRole(Base):
    __tablename__="employee_roles";__table_args__=(UniqueConstraint("workspace_id","name",name="uq_employee_roles_workspace_name"),)
    id: Mapped[uuid.UUID]=mapped_column(UUID(as_uuid=True),primary_key=True,default=uuid.uuid4)
    workspace_id: Mapped[uuid.UUID]=mapped_column(UUID(as_uuid=True),ForeignKey("workspaces.id",ondelete="CASCADE"),index=True)
    name: Mapped[str]=mapped_column(String(120));description: Mapped[str]=mapped_column(String(500),default="")
    is_active: Mapped[bool]=mapped_column(Boolean,default=True);created_at: Mapped[datetime]=mapped_column(DateTime(timezone=True),default=now);updated_at: Mapped[datetime]=mapped_column(DateTime(timezone=True),default=now,onupdate=now)
class User(Base):
    __tablename__="users"
    id: Mapped[uuid.UUID]=mapped_column(UUID(as_uuid=True),primary_key=True,default=uuid.uuid4)
    email: Mapped[str]=mapped_column(String(320),unique=True,index=True); hashed_password: Mapped[str]=mapped_column(String(255)); full_name: Mapped[str]=mapped_column(String(200))
    workspace_id: Mapped[uuid.UUID]=mapped_column(UUID(as_uuid=True),ForeignKey("workspaces.id",ondelete="CASCADE"),index=True,default=settings.workspace_id)
    employee_role_id: Mapped[uuid.UUID|None]=mapped_column(UUID(as_uuid=True),ForeignKey("employee_roles.id",ondelete="RESTRICT"),nullable=True,index=True)
    role: Mapped[UserRole]=mapped_column(Enum(UserRole),default=UserRole.USER); department: Mapped[str]=mapped_column(String(80)); is_active: Mapped[bool]=mapped_column(Boolean,default=True); must_change_password: Mapped[bool]=mapped_column(Boolean,default=False,server_default="false"); auth_version: Mapped[int]=mapped_column(Integer,default=0,server_default="0")
    created_at: Mapped[datetime]=mapped_column(DateTime(timezone=True),default=now); updated_at: Mapped[datetime]=mapped_column(DateTime(timezone=True),default=now,onupdate=now); last_login_at: Mapped[datetime|None]=mapped_column(DateTime(timezone=True),nullable=True)
    employee_role: Mapped[EmployeeRole|None]=relationship(lazy="joined")
    @property
    def system_permission(self): return SystemPermission.ADMIN if self.role==UserRole.ADMIN else SystemPermission.EMPLOYEE
class Document(Base):
    __tablename__="documents"
    id: Mapped[uuid.UUID]=mapped_column(UUID(as_uuid=True),primary_key=True,default=uuid.uuid4); external_document_id: Mapped[str|None]=mapped_column(String(500),nullable=True,index=True)
    workspace_id: Mapped[uuid.UUID]=mapped_column(UUID(as_uuid=True),ForeignKey("workspaces.id",ondelete="CASCADE"),index=True,default=settings.workspace_id)
    source: Mapped[str]=mapped_column(String(80),default="upload"); title: Mapped[str]=mapped_column(String(500)); description: Mapped[str|None]=mapped_column(Text,nullable=True); file_type: Mapped[str]=mapped_column(String(30)); storage_path: Mapped[str|None]=mapped_column(String(1000),nullable=True)
    content_hash: Mapped[str]=mapped_column(String(64),index=True); version: Mapped[int]=mapped_column(Integer,default=1); department: Mapped[str]=mapped_column(String(80)); access_type: Mapped[DocumentAccessType]=mapped_column(Enum(DocumentAccessType,name="documentaccesstype"),default=DocumentAccessType.ALL_EMPLOYEES,server_default="ALL_EMPLOYEES")
    ingestion_status: Mapped[Ingestion]=mapped_column(Enum(Ingestion),default=Ingestion.PENDING); freshness_status: Mapped[Freshness]=mapped_column(Enum(Freshness),default=Freshness.PROCESSING); indexing_error: Mapped[str|None]=mapped_column(Text,nullable=True)
    source_last_modified_at: Mapped[datetime]=mapped_column(DateTime(timezone=True),default=now); indexed_at: Mapped[datetime|None]=mapped_column(DateTime(timezone=True),nullable=True); last_verified_at: Mapped[datetime|None]=mapped_column(DateTime(timezone=True),nullable=True); created_at: Mapped[datetime]=mapped_column(DateTime(timezone=True),default=now)
    indexed_content_hash: Mapped[str|None]=mapped_column(String(64),nullable=True); indexed_version: Mapped[int|None]=mapped_column(Integer,nullable=True); indexed_fingerprint: Mapped[str|None]=mapped_column(String(64),nullable=True); indexed_embedding_fingerprint: Mapped[str|None]=mapped_column(String(64),nullable=True); chunk_count: Mapped[int]=mapped_column(Integer,default=0); indexing_progress: Mapped[int]=mapped_column(Integer,default=0); indexing_failed_at: Mapped[datetime|None]=mapped_column(DateTime(timezone=True),nullable=True); storage_mtime_ns: Mapped[int|None]=mapped_column(BigInteger,nullable=True); storage_size: Mapped[int|None]=mapped_column(BigInteger,nullable=True)
    chunks: Mapped[list["DocumentChunk"]]=relationship(cascade="all, delete-orphan",back_populates="document"); acls: Mapped[list["DocumentACL"]]=relationship(cascade="all, delete-orphan",back_populates="document")
class DocumentACL(Base):
    __tablename__="document_acls"; __table_args__=(UniqueConstraint("document_id","grantee_type","grantee_id"),)
    id: Mapped[uuid.UUID]=mapped_column(UUID(as_uuid=True),primary_key=True,default=uuid.uuid4); document_id: Mapped[uuid.UUID]=mapped_column(ForeignKey("documents.id",ondelete="CASCADE"),index=True)
    workspace_id: Mapped[uuid.UUID]=mapped_column(UUID(as_uuid=True),ForeignKey("workspaces.id",ondelete="CASCADE"),index=True,default=settings.workspace_id)
    grantee_type: Mapped[str]=mapped_column(String(20)); grantee_id: Mapped[str]=mapped_column(String(320)); can_read: Mapped[bool]=mapped_column(Boolean,default=True)
    document: Mapped[Document]=relationship(back_populates="acls")
class DocumentChunk(Base):
    __tablename__="document_chunks"
    id: Mapped[uuid.UUID]=mapped_column(UUID(as_uuid=True),primary_key=True,default=uuid.uuid4); document_id: Mapped[uuid.UUID]=mapped_column(ForeignKey("documents.id",ondelete="CASCADE"),index=True)
    workspace_id: Mapped[uuid.UUID]=mapped_column(UUID(as_uuid=True),ForeignKey("workspaces.id",ondelete="CASCADE"),index=True,default=settings.workspace_id)
    department: Mapped[str]=mapped_column(String(80))
    chunk_index: Mapped[int]=mapped_column(Integer); content: Mapped[str]=mapped_column(Text); page_number: Mapped[int|None]=mapped_column(Integer,nullable=True); token_count: Mapped[int]=mapped_column(Integer,default=0); embedding: Mapped[list|None]=mapped_column(Vector(1536),nullable=True)
    document: Mapped[Document]=relationship(back_populates="chunks")
class IndexingJob(Base):
    __tablename__="document_indexing_jobs"
    __table_args__=(UniqueConstraint("document_id","target_hash",name="uq_index_job_document_hash"),)
    id: Mapped[uuid.UUID]=mapped_column(UUID(as_uuid=True),primary_key=True,default=uuid.uuid4)
    document_id: Mapped[uuid.UUID]=mapped_column(ForeignKey("documents.id",ondelete="CASCADE"),index=True)
    workspace_id: Mapped[uuid.UUID]=mapped_column(UUID(as_uuid=True),ForeignKey("workspaces.id",ondelete="CASCADE"),index=True)
    target_version: Mapped[int]=mapped_column(Integer)
    target_hash: Mapped[str]=mapped_column(String(64),index=True)
    target_fingerprint: Mapped[str|None]=mapped_column(String(64),nullable=True)
    status: Mapped[str]=mapped_column(String(20),default="QUEUED",index=True)
    attempts: Mapped[int]=mapped_column(Integer,default=0)
    retry_count: Mapped[int]=mapped_column(Integer,default=0,server_default="0")
    provider_error_type: Mapped[str|None]=mapped_column(String(120),nullable=True)
    progress: Mapped[int]=mapped_column(Integer,default=0)
    available_at: Mapped[datetime]=mapped_column(DateTime(timezone=True),default=now,index=True)
    locked_until: Mapped[datetime|None]=mapped_column(DateTime(timezone=True),nullable=True)
    old_storage_path: Mapped[str|None]=mapped_column(String(1000),nullable=True)
    supersedes_document_id: Mapped[uuid.UUID|None]=mapped_column(UUID(as_uuid=True),nullable=True)
    last_error: Mapped[str|None]=mapped_column(Text,nullable=True)
    created_at: Mapped[datetime]=mapped_column(DateTime(timezone=True),default=now)
    updated_at: Mapped[datetime]=mapped_column(DateTime(timezone=True),default=now,onupdate=now)
    started_at: Mapped[datetime|None]=mapped_column(DateTime(timezone=True),nullable=True)
    finished_at: Mapped[datetime|None]=mapped_column(DateTime(timezone=True),nullable=True)
class Conversation(Base):
    __tablename__="conversations"
    id: Mapped[uuid.UUID]=mapped_column(UUID(as_uuid=True),primary_key=True,default=uuid.uuid4); user_id: Mapped[uuid.UUID]=mapped_column(ForeignKey("users.id",ondelete="CASCADE"),index=True); title: Mapped[str]=mapped_column(String(300),default="New conversation"); created_at: Mapped[datetime]=mapped_column(DateTime(timezone=True),default=now); updated_at: Mapped[datetime]=mapped_column(DateTime(timezone=True),default=now,onupdate=now)
class Message(Base):
    __tablename__="messages"
    id: Mapped[uuid.UUID]=mapped_column(UUID(as_uuid=True),primary_key=True,default=uuid.uuid4); conversation_id: Mapped[uuid.UUID]=mapped_column(ForeignKey("conversations.id",ondelete="CASCADE"),index=True); role: Mapped[str]=mapped_column(String(20)); content: Mapped[str]=mapped_column(Text); created_at: Mapped[datetime]=mapped_column(DateTime(timezone=True),default=now)
class MessageCitation(Base):
    __tablename__="message_citations"
    id: Mapped[uuid.UUID]=mapped_column(UUID(as_uuid=True),primary_key=True,default=uuid.uuid4); message_id: Mapped[uuid.UUID]=mapped_column(ForeignKey("messages.id",ondelete="CASCADE"),index=True); chunk_id: Mapped[uuid.UUID]=mapped_column(ForeignKey("document_chunks.id")); document_id: Mapped[uuid.UUID]=mapped_column(ForeignKey("documents.id")); document_title: Mapped[str]=mapped_column(String(500)); page_number: Mapped[int|None]=mapped_column(Integer,nullable=True); excerpt: Mapped[str]=mapped_column(Text); reference_id: Mapped[str|None]=mapped_column(String(40),nullable=True)
class SearchHistory(Base):
    __tablename__="search_history"
    id: Mapped[uuid.UUID]=mapped_column(UUID(as_uuid=True),primary_key=True,default=uuid.uuid4); user_id: Mapped[uuid.UUID]=mapped_column(ForeignKey("users.id",ondelete="CASCADE"),index=True); search_query: Mapped[str]=mapped_column(String(1000)); created_at: Mapped[datetime]=mapped_column(DateTime(timezone=True),default=now)
class QueryFeedback(Base):
    __tablename__="query_feedback"
    id: Mapped[uuid.UUID]=mapped_column(UUID(as_uuid=True),primary_key=True,default=uuid.uuid4); message_id: Mapped[uuid.UUID]=mapped_column(ForeignKey("messages.id"),index=True); user_id: Mapped[uuid.UUID]=mapped_column(ForeignKey("users.id")); rating: Mapped[str]=mapped_column(String(20)); reason: Mapped[str|None]=mapped_column(String(80),nullable=True); created_at: Mapped[datetime]=mapped_column(DateTime(timezone=True),default=now)
class CitationInteraction(Base):
    __tablename__="citation_interactions"
    id: Mapped[uuid.UUID]=mapped_column(UUID(as_uuid=True),primary_key=True,default=uuid.uuid4); user_id: Mapped[uuid.UUID]=mapped_column(ForeignKey("users.id")); citation_id: Mapped[uuid.UUID]=mapped_column(ForeignKey("message_citations.id")); event: Mapped[str]=mapped_column(String(30)); created_at: Mapped[datetime]=mapped_column(DateTime(timezone=True),default=now)
class Escalation(Base):
    __tablename__="escalations"
    id: Mapped[uuid.UUID]=mapped_column(UUID(as_uuid=True),primary_key=True,default=uuid.uuid4); user_id: Mapped[uuid.UUID]=mapped_column(ForeignKey("users.id")); message_id: Mapped[uuid.UUID]=mapped_column(ForeignKey("messages.id")); query: Mapped[str]=mapped_column(Text); status: Mapped[str]=mapped_column(String(30),default="OPEN"); created_at: Mapped[datetime]=mapped_column(DateTime(timezone=True),default=now)
class AuditLog(Base):
    __tablename__="audit_logs"
    id: Mapped[uuid.UUID]=mapped_column(UUID(as_uuid=True),primary_key=True,default=uuid.uuid4); user_id: Mapped[uuid.UUID|None]=mapped_column(ForeignKey("users.id"),nullable=True); action: Mapped[str]=mapped_column(String(100)); resource: Mapped[str]=mapped_column(String(300)); status: Mapped[str]=mapped_column(String(20)); details: Mapped[dict]=mapped_column(JSON().with_variant(JSONB,"postgresql"),default=dict); created_at: Mapped[datetime]=mapped_column(DateTime(timezone=True),default=now)
class QueryEvent(Base):
    __tablename__="query_events"
    id: Mapped[uuid.UUID]=mapped_column(UUID(as_uuid=True),primary_key=True,default=uuid.uuid4)
    workspace_id: Mapped[uuid.UUID]=mapped_column(UUID(as_uuid=True),ForeignKey("workspaces.id",ondelete="CASCADE"),index=True,default=settings.workspace_id)
    user_id: Mapped[uuid.UUID]=mapped_column(ForeignKey("users.id",ondelete="CASCADE"),index=True)
    outcome: Mapped[str]=mapped_column(String(30),index=True)
    response_ms: Mapped[int]=mapped_column(Integer,default=0)
    retrieved_chunks: Mapped[int]=mapped_column(Integer,default=0)
    relevance_score: Mapped[float|None]=mapped_column(Float,nullable=True)
    created_at: Mapped[datetime]=mapped_column(DateTime(timezone=True),default=now,index=True)
class DocumentRetrievalEvent(Base):
    __tablename__="document_retrieval_events"
    id: Mapped[uuid.UUID]=mapped_column(UUID(as_uuid=True),primary_key=True,default=uuid.uuid4)
    workspace_id: Mapped[uuid.UUID]=mapped_column(UUID(as_uuid=True),ForeignKey("workspaces.id",ondelete="CASCADE"),index=True,default=settings.workspace_id)
    document_id: Mapped[uuid.UUID]=mapped_column(ForeignKey("documents.id",ondelete="CASCADE"),index=True)
    user_id: Mapped[uuid.UUID]=mapped_column(ForeignKey("users.id",ondelete="CASCADE"),index=True)
    created_at: Mapped[datetime]=mapped_column(DateTime(timezone=True),default=now,index=True)
