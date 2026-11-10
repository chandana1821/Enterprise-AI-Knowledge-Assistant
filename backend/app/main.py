import asyncio, hashlib, json, logging, os, uuid
from time import perf_counter
from pathlib import Path
from datetime import datetime, timezone, timedelta
from fastapi import FastAPI, Depends, HTTPException, UploadFile, File, Form, Query, Request
from fastapi.responses import FileResponse, JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, ConfigDict, EmailStr, Field, field_validator, model_validator
from fastapi.exceptions import RequestValidationError
from sqlalchemy import select, func, delete, desc, text, and_, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession
from .config import settings
from .db import Base, engine, get_db
from .models import *
from .security import current_user, admin_user, verify_password, hash_password, issue_token, readable_document_predicate
from .employee_roles import ensure_default_employee_roles
from .rag import retrieve, recheck_access, answer, NO_ANSWER, AIProviderError
from .indexing import enqueue_document, scan_and_queue_stale, worker_loop

app=FastAPI(title="Knowbase Enterprise Knowledge API",version="1.0.0")
logger=logging.getLogger(__name__)

@app.exception_handler(RequestValidationError)
async def redact_password_validation_errors(request:Request,exc:RequestValidationError):
    safe_errors=[]
    for error in exc.errors():
        item={key:value for key,value in error.items() if key not in {"input","ctx"}}
        if any("password" in str(part).lower() for part in error.get("loc",())):item["msg"]="Password does not meet the required format"
        safe_errors.append(item)
    return JSONResponse(status_code=422,content={"detail":safe_errors})
indexing_worker_task:asyncio.Task|None=None
app.add_middleware(CORSMiddleware,allow_origins=os.getenv("CORS_ORIGINS","http://localhost:5173").split(","),allow_credentials=True,allow_methods=["*"],allow_headers=["*"])

class LoginBody(BaseModel):
    model_config=ConfigDict(extra="forbid")
    email:EmailStr
    password:str=Field(max_length=72)
    @field_validator("email",mode="before")
    @classmethod
    def normalize_email(cls,value):return value.strip().lower() if isinstance(value,str) else value
    @field_validator("password")
    @classmethod
    def bcrypt_password_size(cls,value):
        if len(value.encode("utf-8"))>72:raise ValueError("Password must be at most 72 UTF-8 bytes")
        return value
class ChatBody(BaseModel): message:str=Field(min_length=1,max_length=10000); conversation_id:uuid.UUID|None=None
class ProfileUpdateBody(BaseModel):
    model_config=ConfigDict(extra="forbid")
    full_name:str=Field(min_length=2,max_length=200)
    @field_validator("full_name")
    @classmethod
    def normalize_profile_name(cls,value):
        value=value.strip()
        if len(value)<2:raise ValueError("Full name must contain at least 2 characters")
        return value
class ChangePasswordBody(BaseModel):
    model_config=ConfigDict(extra="forbid")
    current_password:str=Field(min_length=1,max_length=72)
    new_password:str=Field(min_length=12,max_length=72)
    confirm_new_password:str=Field(min_length=12,max_length=72)
    @model_validator(mode="after")
    def validate_passwords(self):
        if self.new_password!=self.confirm_new_password:raise ValueError("New passwords do not match")
        if self.current_password==self.new_password:raise ValueError("Choose a password different from your current password")
        for value in (self.current_password,self.new_password):
            if len(value.encode("utf-8"))>72:raise ValueError("Password must be at most 72 UTF-8 bytes")
        if not any(c.islower() for c in self.new_password) or not any(c.isupper() for c in self.new_password) or not any(c.isdigit() for c in self.new_password) or not any(not c.isalnum() for c in self.new_password):raise ValueError("New password must include uppercase, lowercase, a number, and a symbol")
        return self
class SearchHistoryBody(BaseModel):
    model_config=ConfigDict(extra="forbid")
    query:str=Field(min_length=1,max_length=1000)
    @field_validator("query")
    @classmethod
    def normalize_query(cls,value):
        value=value.strip()
        if not value:raise ValueError("Search query cannot be empty")
        return value
class FeedbackBody(BaseModel): message_id:uuid.UUID; rating:str; reason:str|None=None
class EscalationBody(BaseModel): message_id:uuid.UUID; query:str
class DocumentUpdateBody(BaseModel):
    model_config=ConfigDict(extra="forbid")
    title:str|None=Field(default=None,min_length=1,max_length=500)
    department:str|None=Field(default=None,min_length=1,max_length=80)
    description:str|None=Field(default=None,max_length=4000)
class DocumentAccessBody(BaseModel):
    model_config=ConfigDict(extra="forbid")
    access_type:DocumentAccessType
    employee_role_ids:list[uuid.UUID]=Field(default_factory=list,max_length=500)
    user_ids:list[uuid.UUID]=Field(default_factory=list,max_length=500)
    @model_validator(mode="after")
    def validate_access_grants(self):
        if self.access_type==DocumentAccessType.SPECIFIC_EMPLOYEE_ROLES and not self.employee_role_ids:raise ValueError("Select at least one employee role")
        if self.access_type==DocumentAccessType.SPECIFIC_USERS and not self.user_ids:raise ValueError("Select at least one user")
        if self.access_type!=DocumentAccessType.SPECIFIC_EMPLOYEE_ROLES and self.employee_role_ids:raise ValueError("Employee roles are only allowed for Specific Employee Roles access")
        if self.access_type!=DocumentAccessType.SPECIFIC_USERS and self.user_ids:raise ValueError("Users are only allowed for Specific Users access")
        return self
    @field_validator("employee_role_ids")
    @classmethod
    def unique_employee_roles(cls,values):return list(dict.fromkeys(values))
class AdminUserUpdateBody(BaseModel):
    model_config=ConfigDict(extra="forbid")
    full_name:str|None=Field(default=None,min_length=2,max_length=200)
    system_permission:SystemPermission|None=None
    employee_role_id:uuid.UUID|None=None
    is_active:bool|None=None
    @field_validator("full_name")
    @classmethod
    def normalize_employee_name(cls,value):
        value=value.strip() if value is not None else value
        if value is not None and len(value)<2:raise ValueError("Full name must contain at least 2 characters")
        return value
class AdminEmployeeCreateBody(BaseModel):
    model_config=ConfigDict(extra="forbid")
    full_name:str=Field(min_length=2,max_length=200)
    email:EmailStr
    password:str=Field(min_length=12,max_length=72)
    system_permission:SystemPermission=SystemPermission.EMPLOYEE
    employee_role_id:uuid.UUID|None=None
    is_active:bool=True
    @field_validator("full_name")
    @classmethod
    def normalize_employee_name(cls,value):
        value=value.strip()
        if len(value)<2:raise ValueError("Full name must contain at least 2 characters")
        return value
    @field_validator("email",mode="before")
    @classmethod
    def normalize_employee_email(cls,value):return value.strip().lower() if isinstance(value,str) else value
    @field_validator("password")
    @classmethod
    def validate_initial_password(cls,value):
        if len(value.encode("utf-8"))>72:raise ValueError("Password must be at most 72 UTF-8 bytes")
        if not any(c.islower() for c in value) or not any(c.isupper() for c in value) or not any(c.isdigit() for c in value) or not any(not c.isalnum() for c in value):
            raise ValueError("Initial password must include uppercase, lowercase, a number, and a symbol")
        return value
class AdminPasswordResetBody(BaseModel):
    model_config=ConfigDict(extra="forbid")
    temporary_password:str=Field(min_length=12,max_length=72)
    @field_validator("temporary_password")
    @classmethod
    def validate_temporary_password(cls,value):
        if len(value.encode("utf-8"))>72:raise ValueError("Password must be at most 72 UTF-8 bytes")
        if not any(c.islower() for c in value) or not any(c.isupper() for c in value) or not any(c.isdigit() for c in value) or not any(not c.isalnum() for c in value):
            raise ValueError("Temporary password must include uppercase, lowercase, a number, and a symbol")
        return value
class AdminUserStatusBody(BaseModel):
    model_config=ConfigDict(extra="forbid")
    is_active:bool
class EmployeeRoleCreateBody(BaseModel):
    model_config=ConfigDict(extra="forbid")
    name:str=Field(min_length=2,max_length=120)
    description:str=Field(default="",max_length=500)
    @field_validator("name")
    @classmethod
    def normalize_role_name(cls,value):
        value=value.strip()
        if len(value)<2:raise ValueError("Role name must contain at least two characters")
        return value
class EmployeeRoleUpdateBody(BaseModel):
    model_config=ConfigDict(extra="forbid")
    name:str|None=Field(default=None,min_length=2,max_length=120)
    description:str|None=Field(default=None,max_length=500)
    is_active:bool|None=None
    @field_validator("name")
    @classmethod
    def normalize_role_name(cls,value):return value.strip() if value is not None else value

@app.on_event("startup")
async def startup():
    workspace_id=str(settings.workspace_id)
    async with engine.begin() as conn:
        await conn.execute(text("CREATE EXTENSION IF NOT EXISTS vector"))
        await conn.execute(text("DO $$ BEGIN CREATE TYPE documentaccesstype AS ENUM ('ALL_EMPLOYEES','ADMIN_ONLY','SPECIFIC_ROLES','SPECIFIC_EMPLOYEE_ROLES','SPECIFIC_USERS'); EXCEPTION WHEN duplicate_object THEN NULL; END $$"))
        await conn.execute(text("DO $$ BEGIN CREATE TYPE freshness AS ENUM ('FRESH','STALE','QUEUED','PROCESSING','RETRYING','FAILED','DELETED'); EXCEPTION WHEN duplicate_object THEN NULL; END $$"))
    # PostgreSQL requires newly added enum values to be committed before use.
    async with engine.begin() as conn:
        await conn.execute(text("ALTER TYPE documentaccesstype ADD VALUE IF NOT EXISTS 'SPECIFIC_EMPLOYEE_ROLES'"))
        for status in ("QUEUED", "RETRYING"):
            await conn.execute(text(f"ALTER TYPE freshness ADD VALUE IF NOT EXISTS '{status}'"))
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
        await conn.execute(text("INSERT INTO workspaces (id,name,created_at) VALUES (:id,:name,CURRENT_TIMESTAMP) ON CONFLICT (id) DO UPDATE SET name=EXCLUDED.name"),{"id":workspace_id,"name":settings.workspace_name})
        await conn.execute(text("ALTER TABLE users ADD COLUMN IF NOT EXISTS workspace_id UUID"))
        await conn.execute(text("ALTER TABLE users ADD COLUMN IF NOT EXISTS last_login_at TIMESTAMPTZ"))
        await conn.execute(text("ALTER TABLE users ADD COLUMN IF NOT EXISTS employee_role_id UUID"))
        await conn.execute(text("ALTER TABLE users ADD COLUMN IF NOT EXISTS must_change_password BOOLEAN NOT NULL DEFAULT FALSE"))
        await conn.execute(text("ALTER TABLE users ADD COLUMN IF NOT EXISTS auth_version INTEGER NOT NULL DEFAULT 0"))
        await conn.execute(text("CREATE INDEX IF NOT EXISTS ix_users_employee_role_id ON users(employee_role_id)"))
        await conn.execute(text("ALTER TABLE documents ADD COLUMN IF NOT EXISTS workspace_id UUID"))
        await conn.execute(text("ALTER TABLE documents ADD COLUMN IF NOT EXISTS access_type documentaccesstype NOT NULL DEFAULT 'ALL_EMPLOYEES'"))
        await conn.execute(text("ALTER TABLE documents ADD COLUMN IF NOT EXISTS description TEXT"))
        await conn.execute(text("ALTER TABLE document_acls ADD COLUMN IF NOT EXISTS workspace_id UUID"))
        await conn.execute(text("ALTER TABLE document_chunks ADD COLUMN IF NOT EXISTS workspace_id UUID"))
        await conn.execute(text("ALTER TABLE document_chunks ADD COLUMN IF NOT EXISTS department VARCHAR(80)"))
        await conn.execute(text("ALTER TABLE document_indexing_jobs ADD COLUMN IF NOT EXISTS retry_count INTEGER NOT NULL DEFAULT 0"))
        await conn.execute(text("ALTER TABLE document_indexing_jobs ADD COLUMN IF NOT EXISTS provider_error_type VARCHAR(120)"))
        await conn.execute(text("UPDATE users SET workspace_id=:workspace_id WHERE workspace_id IS NULL"),{"workspace_id":workspace_id})
        await conn.execute(text("UPDATE documents SET workspace_id=:workspace_id WHERE workspace_id IS NULL"),{"workspace_id":workspace_id})
        await conn.execute(text("UPDATE document_acls a SET workspace_id=d.workspace_id FROM documents d WHERE a.document_id=d.id AND a.workspace_id IS NULL"))
        await conn.execute(text("UPDATE document_chunks c SET workspace_id=d.workspace_id,department=d.department FROM documents d WHERE c.document_id=d.id AND (c.workspace_id IS NULL OR c.department IS NULL)"))
        await conn.execute(text("ALTER TABLE users ALTER COLUMN workspace_id SET DEFAULT '"+workspace_id+"'"))
        await conn.execute(text("ALTER TABLE documents ALTER COLUMN workspace_id SET DEFAULT '"+workspace_id+"'"))
        await conn.execute(text("ALTER TABLE document_acls ALTER COLUMN workspace_id SET DEFAULT '"+workspace_id+"'"))
        await conn.execute(text("ALTER TABLE document_chunks ALTER COLUMN workspace_id SET DEFAULT '"+workspace_id+"'"))
        await conn.execute(text("ALTER TABLE users ALTER COLUMN workspace_id SET NOT NULL"))
        await conn.execute(text("ALTER TABLE documents ALTER COLUMN workspace_id SET NOT NULL"))
        await conn.execute(text("ALTER TABLE document_acls ALTER COLUMN workspace_id SET NOT NULL"))
        await conn.execute(text("ALTER TABLE document_chunks ALTER COLUMN workspace_id SET NOT NULL"))
        await conn.execute(text("ALTER TABLE document_chunks ALTER COLUMN department SET NOT NULL"))
        await conn.execute(text("""
            DO $$ BEGIN
              IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conrelid='users'::regclass AND confrelid='workspaces'::regclass) THEN
                ALTER TABLE users ADD CONSTRAINT fk_users_workspace FOREIGN KEY (workspace_id) REFERENCES workspaces(id) ON DELETE CASCADE;
              END IF;
              IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conrelid='documents'::regclass AND confrelid='workspaces'::regclass) THEN
                ALTER TABLE documents ADD CONSTRAINT fk_documents_workspace FOREIGN KEY (workspace_id) REFERENCES workspaces(id) ON DELETE CASCADE;
              END IF;
              IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conrelid='document_acls'::regclass AND confrelid='workspaces'::regclass) THEN
                ALTER TABLE document_acls ADD CONSTRAINT fk_document_acls_workspace FOREIGN KEY (workspace_id) REFERENCES workspaces(id) ON DELETE CASCADE;
              END IF;
              IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conrelid='document_chunks'::regclass AND confrelid='workspaces'::regclass) THEN
                ALTER TABLE document_chunks ADD CONSTRAINT fk_document_chunks_workspace FOREIGN KEY (workspace_id) REFERENCES workspaces(id) ON DELETE CASCADE;
              END IF;
            END $$
        """))
        await conn.execute(text("ALTER TABLE users ADD COLUMN IF NOT EXISTS updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP"))
        await conn.execute(text("ALTER TABLE documents ADD COLUMN IF NOT EXISTS indexing_error TEXT"))
        await conn.execute(text("ALTER TABLE documents ADD COLUMN IF NOT EXISTS indexed_content_hash VARCHAR(64)"))
        await conn.execute(text("ALTER TABLE documents ADD COLUMN IF NOT EXISTS indexed_version INTEGER"))
        await conn.execute(text("ALTER TABLE documents ADD COLUMN IF NOT EXISTS indexed_fingerprint VARCHAR(64)"))
        await conn.execute(text("ALTER TABLE documents ADD COLUMN IF NOT EXISTS indexed_embedding_fingerprint VARCHAR(64)"))
        await conn.execute(text("ALTER TABLE document_indexing_jobs ADD COLUMN IF NOT EXISTS target_fingerprint VARCHAR(64)"))
        await conn.execute(text("ALTER TABLE documents ADD COLUMN IF NOT EXISTS chunk_count INTEGER NOT NULL DEFAULT 0"))
        await conn.execute(text("ALTER TABLE documents ADD COLUMN IF NOT EXISTS indexing_progress INTEGER NOT NULL DEFAULT 0"))
        await conn.execute(text("ALTER TABLE documents ADD COLUMN IF NOT EXISTS indexing_failed_at TIMESTAMPTZ"))
        await conn.execute(text("ALTER TABLE documents ADD COLUMN IF NOT EXISTS storage_mtime_ns BIGINT"))
        await conn.execute(text("ALTER TABLE documents ADD COLUMN IF NOT EXISTS storage_size BIGINT"))
        await conn.execute(text("UPDATE documents d SET indexed_version=j.target_version FROM document_indexing_jobs j WHERE d.id=j.document_id AND j.status='SUCCEEDED' AND j.target_hash=d.indexed_content_hash AND d.indexed_version IS NULL"))
        await conn.execute(text("UPDATE documents d SET indexed_version=d.version,chunk_count=(SELECT count(*) FROM document_chunks c WHERE c.document_id=d.id AND c.embedding IS NOT NULL) WHERE d.indexed_version IS NULL AND d.freshness_status::text='FRESH' AND d.ingestion_status::text='INDEXED' AND d.indexed_content_hash=d.content_hash AND EXISTS (SELECT 1 FROM document_chunks c WHERE c.document_id=d.id AND c.embedding IS NOT NULL)"))
        await conn.execute(text("ALTER TABLE conversations ADD COLUMN IF NOT EXISTS updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP"))
        await conn.execute(text("ALTER TABLE message_citations ADD COLUMN IF NOT EXISTS reference_id VARCHAR(40)"))
        await conn.execute(text("ALTER TYPE userrole ADD VALUE IF NOT EXISTS 'USER'"))
        await conn.execute(text("UPDATE documents SET access_type='SPECIFIC_EMPLOYEE_ROLES' WHERE access_type::text='SPECIFIC_ROLES'"))
        await conn.execute(text("CREATE UNIQUE INDEX IF NOT EXISTS uq_users_email_lower ON users (lower(email))"))
        await conn.execute(text("CREATE INDEX IF NOT EXISTS ix_chunks_embedding_hnsw ON document_chunks USING hnsw (embedding vector_cosine_ops)"))
        # Idempotent schema migration: obsolete classification metadata is removed without touching documents, chunks, or access grants.
        await conn.execute(text("ALTER TABLE documents DROP COLUMN IF EXISTS classification"))
        await conn.execute(text("ALTER TABLE document_chunks DROP COLUMN IF EXISTS classification"))
        await conn.execute(text("ALTER TABLE users DROP COLUMN IF EXISTS clearance_level"))
        await conn.execute(text("DROP TYPE IF EXISTS clearance"))
    # Migrate legacy employee accounts to the single normal-user role after USER is committed to the enum.
    async with engine.begin() as conn:
        await conn.execute(text("UPDATE users SET role='USER' WHERE role::text='EMPLOYEE'"))
    # Add the employee-role FK after create_all has created employee_roles. Existing accounts and
    # documents are mapped in place; document chunks and vectors are deliberately untouched.
    async with engine.begin() as conn:
        await conn.execute(text("""DO $$ BEGIN
          IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conrelid='users'::regclass AND confrelid='employee_roles'::regclass) THEN
            ALTER TABLE users ADD CONSTRAINT fk_users_employee_role FOREIGN KEY (employee_role_id) REFERENCES employee_roles(id) ON DELETE RESTRICT;
          END IF;
        END $$"""))
    async with AsyncSession(engine,expire_on_commit=False) as db:
        workspace_ids=(await db.scalars(select(Workspace.id))).all()
        for ws_id in workspace_ids:
            roles=await ensure_default_employee_roles(db,ws_id)
            await db.execute(update(User).where(User.workspace_id==ws_id,User.role==UserRole.ADMIN,User.employee_role_id.is_(None)).values(employee_role_id=roles['ADMIN'].id))
            await db.execute(update(User).where(User.workspace_id==ws_id,User.role==UserRole.USER,User.employee_role_id.is_(None)).values(employee_role_id=roles['Unassigned'].id))
            # Convert legacy ADMIN/USER role ACLs to employee-role grants without rebuilding vectors.
            for legacy_name,target_name in (("ADMIN","ADMIN"),("USER","Unassigned")):
                target=roles[target_name]
                await db.execute(text("UPDATE document_acls SET grantee_type='EMPLOYEE_ROLE',grantee_id=:role_id WHERE workspace_id=:ws AND grantee_type='ROLE' AND grantee_id=:legacy"),{"role_id":str(target.id),"ws":str(ws_id),"legacy":legacy_name})
        await db.commit()
    Path(settings.upload_dir).mkdir(parents=True,exist_ok=True)
    logging.getLogger("uvicorn.error").info(
        "AI Provider: Gemini; Embedding Model: %s; Answer Model: %s",
        settings.gemini_embedding_model,settings.gemini_model)
    await scan_and_queue_stale()
    global indexing_worker_task
    indexing_worker_task=asyncio.create_task(worker_loop(),name="document-indexing-worker")

@app.on_event("shutdown")
async def shutdown_indexing_worker():
    global indexing_worker_task
    if indexing_worker_task:
        indexing_worker_task.cancel()
        try:await indexing_worker_task
        except asyncio.CancelledError:pass
        indexing_worker_task=None

@app.get("/health")
async def health(): return {"status":"ok"}

@app.post("/api/auth/register",status_code=403)
async def register():
    raise HTTPException(403,"Self-registration is disabled. Contact your workspace administrator for an employee account.")

async def flag_stale(db:AsyncSession):
    cutoff=datetime.now(timezone.utc)-timedelta(minutes=settings.freshness_sla_minutes)
    expired=(await db.scalars(select(Document).where(Document.freshness_status==Freshness.FRESH,Document.last_verified_at<cutoff))).all()
    for doc in expired:
        if doc.source=="upload" and doc.storage_path:
            await enqueue_document(db,doc)
        else:
            doc.freshness_status=Freshness.STALE
    await db.commit()

@app.post("/api/auth/login")
async def login(body:LoginBody,db:AsyncSession=Depends(get_db)):
    user=await db.scalar(select(User).where(func.lower(User.email)==str(body.email).lower()))
    if not user or not user.is_active or not verify_password(body.password,user.hashed_password): raise HTTPException(401,"Invalid email or password")
    user.last_login_at=datetime.now(timezone.utc)
    db.add(AuditLog(user_id=user.id,action="LOGIN",resource="session",status="SUCCESS")); await db.commit()
    return {"access_token":issue_token(user),"token_type":"bearer","must_change_password":user.must_change_password,"user":safe_user(user)}

def safe_user(user:User):
    employee_role=user.employee_role
    return {"id":str(user.id),"email":user.email,"full_name":user.full_name,"name":user.full_name,"role":user.role.value,"system_permission":user.system_permission.value,"employee_role_id":str(user.employee_role_id) if user.employee_role_id else None,"employee_role":{"id":str(employee_role.id),"name":employee_role.name,"description":employee_role.description,"is_active":employee_role.is_active} if employee_role else None,"employee_role_name":employee_role.name if employee_role else None,"department":user.department,"is_active":user.is_active,"must_change_password":user.must_change_password,"created_at":user.created_at.isoformat() if user.created_at else None,"updated_at":user.updated_at.isoformat() if user.updated_at else None,"last_login_at":user.last_login_at.isoformat() if user.last_login_at else None}

@app.get("/api/auth/me")
async def me(user:User=Depends(current_user)): return safe_user(user)

@app.patch("/api/profile")
@app.patch("/api/auth/profile")
async def update_profile(body:ProfileUpdateBody,db:AsyncSession=Depends(get_db),user:User=Depends(current_user)):
    user.full_name=body.full_name
    await db.commit()
    return safe_user(user)

@app.post("/api/profile/change-password")
async def change_password(body:ChangePasswordBody,db:AsyncSession=Depends(get_db),user:User=Depends(current_user)):
    if not verify_password(body.current_password,user.hashed_password):raise HTTPException(400,"Current password is incorrect")
    user.hashed_password=hash_password(body.new_password)
    user.must_change_password=False
    user.auth_version+=1
    user.updated_at=datetime.now(timezone.utc)
    db.add(AuditLog(user_id=user.id,action="PASSWORD_CHANGE",resource="account",status="SUCCESS"))
    await db.commit()
    await db.refresh(user)
    return {"message":"Password updated successfully","access_token":issue_token(user),"token_type":"bearer","user":safe_user(user)}

@app.get("/api/conversations")
async def list_conversations(db:AsyncSession=Depends(get_db),user:User=Depends(current_user)):
    rows=(await db.scalars(select(Conversation).where(Conversation.user_id==user.id).order_by(desc(Conversation.updated_at),desc(Conversation.created_at)).limit(100))).all()
    return [{"id":str(c.id),"title":c.title,"created_at":c.created_at.isoformat(),"updated_at":c.updated_at.isoformat()} for c in rows]

@app.get("/api/conversations/{conversation_id}")
async def get_conversation(conversation_id:uuid.UUID,db:AsyncSession=Depends(get_db),user:User=Depends(current_user)):
    conv=await db.scalar(select(Conversation).where(Conversation.id==conversation_id,Conversation.user_id==user.id))
    if not conv:raise HTTPException(404,"Conversation not found")
    messages=(await db.scalars(select(Message).where(Message.conversation_id==conv.id).order_by(Message.created_at,Message.id))).all()
    results=[]
    for msg in messages:
        citations=[];content=msg.content
        if msg.role=="assistant":
            citation_count=await db.scalar(select(func.count()).select_from(MessageCitation).where(MessageCitation.message_id==msg.id))
            citations=(await db.scalars(select(MessageCitation).join(Document,Document.id==MessageCitation.document_id).where(MessageCitation.message_id==msg.id,readable_document_predicate(user)).order_by(MessageCitation.id))).all()
            if len(citations)!=citation_count:
                content="This saved answer is unavailable because access to one or more source documents has changed."
                citations=[]
        results.append({"id":str(msg.id),"role":msg.role,"content":content,"created_at":msg.created_at.isoformat(),"citations":[{"id":c.reference_id or f"REF_{i+1}","title":c.document_title,"page":c.page_number or 1,"excerpt":c.excerpt} for i,c in enumerate(citations)]})
    return {"id":str(conv.id),"title":conv.title,"created_at":conv.created_at.isoformat(),"updated_at":conv.updated_at.isoformat(),"messages":results}

@app.delete("/api/conversations/{conversation_id}")
async def delete_conversation(conversation_id:uuid.UUID,db:AsyncSession=Depends(get_db),user:User=Depends(current_user)):
    conv=await db.scalar(select(Conversation).where(Conversation.id==conversation_id,Conversation.user_id==user.id))
    if not conv:raise HTTPException(404,"Conversation not found")
    message_ids=select(Message.id).where(Message.conversation_id==conv.id)
    citation_ids=select(MessageCitation.id).where(MessageCitation.message_id.in_(message_ids))
    await db.execute(delete(CitationInteraction).where(CitationInteraction.citation_id.in_(citation_ids)))
    await db.execute(delete(MessageCitation).where(MessageCitation.message_id.in_(message_ids)))
    await db.execute(delete(QueryFeedback).where(QueryFeedback.message_id.in_(message_ids)))
    await db.execute(delete(Escalation).where(Escalation.message_id.in_(message_ids)))
    await db.execute(delete(Message).where(Message.conversation_id==conv.id))
    await db.delete(conv);await db.commit()
    return {"message":"Conversation deleted"}

@app.get("/api/search-history")
async def list_search_history(db:AsyncSession=Depends(get_db),user:User=Depends(current_user)):
    rows=(await db.scalars(select(SearchHistory).where(SearchHistory.user_id==user.id).order_by(desc(SearchHistory.created_at)).limit(100))).all()
    return [{"id":str(row.id),"query":row.search_query,"created_at":row.created_at.isoformat()} for row in rows]

@app.post("/api/search-history",status_code=201)
async def add_search_history(body:SearchHistoryBody,db:AsyncSession=Depends(get_db),user:User=Depends(current_user)):
    row=SearchHistory(user_id=user.id,search_query=body.query)
    db.add(row);await db.commit()
    return {"id":str(row.id),"query":row.search_query,"created_at":row.created_at.isoformat()}

@app.delete("/api/search-history")
async def clear_search_history(db:AsyncSession=Depends(get_db),user:User=Depends(current_user)):
    await db.execute(delete(SearchHistory).where(SearchHistory.user_id==user.id));await db.commit()
    return {"message":"Search history cleared"}

@app.post("/api/chat")
async def chat(body:ChatBody,db:AsyncSession=Depends(get_db),user:User=Depends(current_user)):
    started=perf_counter()
    await flag_stale(db)
    db.add(SearchHistory(user_id=user.id,search_query=body.message))
    if body.conversation_id:
        conv=await db.scalar(select(Conversation).where(Conversation.id==body.conversation_id,Conversation.user_id==user.id))
        if not conv: raise HTTPException(404,"Conversation not found")
    else:
        conv=Conversation(user_id=user.id,title=body.message[:80]);db.add(conv);await db.flush()
    conv.updated_at=datetime.now(timezone.utc)
    db.add(Message(conversation_id=conv.id,role="user",content=body.message));await db.flush()
    try: hits=await retrieve(db,user,body.message)
    except RuntimeError as e:
        elapsed=int((perf_counter()-started)*1000)
        db.add(QueryEvent(workspace_id=user.workspace_id,user_id=user.id,outcome="FAILED",response_ms=elapsed))
        db.add(AuditLog(user_id=user.id,action="QUERY",resource=str(conv.id),status="ERROR",details={"reason":str(e),"outcome":"FAILED","response_ms":elapsed}));await db.commit()
        raise HTTPException(503,"Knowledge service is not configured")
    except AIProviderError as e:
        status=getattr(e,"status_code",None)
        detail=("Gemini embedding quota reached. Retry shortly." if status==429 else "Gemini could not create query embeddings. Check the Gemini API key, availability, and project limits, then retry.")
        elapsed=int((perf_counter()-started)*1000)
        db.add(QueryEvent(workspace_id=user.workspace_id,user_id=user.id,outcome="FAILED",response_ms=elapsed))
        db.add(AuditLog(user_id=user.id,action="QUERY",resource=str(conv.id),status="ERROR",details={"provider":"Gemini","provider_status":status,"error_type":type(e).__name__,"outcome":"FAILED","response_ms":elapsed}));await db.commit()
        raise HTTPException(503,detail)
    # Every citation returned here has passed the SQL authorization filter. Verify ACL again just before prompt assembly.
    hits=[h for h in hits if await recheck_access(db,user,{h[1].id},{h[0].id})]
    for doc_id in {doc.id for _,doc,_ in hits}:
        db.add(DocumentRetrievalEvent(workspace_id=user.workspace_id,document_id=doc_id,user_id=user.id))
    if not hits:
        final=NO_ANSWER; cites=[]
    else:
        cites=[]; contexts=[]
        for i,(chunk,doc,sim) in enumerate(hits,1):
            ref=f"REF_{i}"; excerpt=chunk.content[:700]
            contexts.append((ref,doc.title,excerpt,chunk.page_number));cites.append({"ref":ref,"chunk":chunk,"doc":doc,"excerpt":excerpt})
        try: final=await answer(body.message,contexts)
        except (AIProviderError,RuntimeError) as e:
            status=getattr(e,"status_code",None)
            detail=("Gemini API quota or usage limit reached. Check your Google AI Studio project limits, then retry." if status==429 else "Gemini could not generate an answer. Check the Gemini API key, availability, and project limits, then retry.")
            elapsed=int((perf_counter()-started)*1000)
            db.add(QueryEvent(workspace_id=user.workspace_id,user_id=user.id,outcome="FAILED",response_ms=elapsed,retrieved_chunks=len(hits),relevance_score=sum(h[2] for h in hits)/len(hits) if hits else None))
            db.add(AuditLog(user_id=user.id,action="QUERY",resource=str(conv.id),status="ERROR",details={"provider":"Gemini","provider_status":status,"error_type":type(e).__name__,"outcome":"FAILED","response_ms":elapsed,"authorized_chunks":len(hits)}));await db.commit()
            raise HTTPException(503,detail)
        # If generation returns no authorized references, suppress it completely.
        valid={c[0] for c in contexts}
        import re
        found=set(re.findall(r"\[\[(REF_\d+)\]\]",final))
        if final!=NO_ANSWER and (not found or not found.issubset(valid)): final=NO_ANSWER;cites=[]
        elif final==NO_ANSWER:cites=[]
    msg=Message(conversation_id=conv.id,role="assistant",content=final);db.add(msg);await db.flush()
    out=[]
    for ref in __import__("re").findall(r"\[\[(REF_\d+)\]\]",final):
        citation=next((c for c in cites if c["ref"]==ref),None)
        if not citation: continue
        c=citation;db.add(MessageCitation(message_id=msg.id,chunk_id=c["chunk"].id,document_id=c["doc"].id,document_title=c["doc"].title,page_number=c["chunk"].page_number,excerpt=c["excerpt"],reference_id=ref))
        out.append({"id":ref,"title":c["doc"].title,"page":c["chunk"].page_number or 1,"excerpt":c["excerpt"]})
    outcome="NO_CONTEXT" if not hits else "NO_ANSWER" if final==NO_ANSWER else "ANSWERED"
    elapsed=int((perf_counter()-started)*1000)
    db.add(QueryEvent(workspace_id=user.workspace_id,user_id=user.id,outcome=outcome,response_ms=elapsed,retrieved_chunks=len(hits),relevance_score=sum(h[2] for h in hits)/len(hits) if hits else None))
    db.add(AuditLog(user_id=user.id,action="QUERY",resource=str(conv.id),status="SUCCESS",details={"authorized_chunks":len(hits),"cited":len(out),"outcome":outcome,"response_ms":elapsed}));await db.commit()
    return {"answer":final,"citations":out,"message_id":str(msg.id),"conversation_id":str(conv.id)}

async def apply_document_access(db:AsyncSession,doc:Document,body:DocumentAccessBody,admin:User):
    selected=(await db.scalars(select(User).where(User.workspace_id==admin.workspace_id,User.id.in_(body.user_ids),User.is_active.is_(True)))).all() if body.user_ids else []
    if len(selected)!=len(set(body.user_ids)):raise HTTPException(422,"Every selected user must be active and belong to this workspace")
    roles=(await db.scalars(select(EmployeeRole).where(EmployeeRole.workspace_id==admin.workspace_id,EmployeeRole.id.in_(body.employee_role_ids),EmployeeRole.is_active.is_(True)))).all() if body.employee_role_ids else []
    if len(roles)!=len(set(body.employee_role_ids)):raise HTTPException(422,"Every selected employee role must be active and belong to this workspace")
    await db.execute(delete(DocumentACL).where(DocumentACL.document_id==doc.id))
    doc.access_type=body.access_type
    if body.access_type==DocumentAccessType.SPECIFIC_EMPLOYEE_ROLES:
        for role in roles:db.add(DocumentACL(document_id=doc.id,workspace_id=admin.workspace_id,grantee_type="EMPLOYEE_ROLE",grantee_id=str(role.id),can_read=True))
    elif body.access_type==DocumentAccessType.SPECIFIC_USERS:
        for target in selected:db.add(DocumentACL(document_id=doc.id,workspace_id=admin.workspace_id,grantee_type="USER",grantee_id=str(target.id),can_read=True))

@app.post("/api/documents")
async def upload_document(file:UploadFile=File(...),department:str=Form(...,min_length=1,max_length=80),description:str=Form("",max_length=4000),access_type:DocumentAccessType=Form(DocumentAccessType.ALL_EMPLOYEES),access_employee_role_ids:str=Form("[]"),access_user_ids:str=Form("[]"),db:AsyncSession=Depends(get_db),user:User=Depends(admin_user)):
    try:access=DocumentAccessBody(access_type=access_type,employee_role_ids=json.loads(access_employee_role_ids),user_ids=json.loads(access_user_ids))
    except (ValueError,TypeError) as exc:raise HTTPException(422,"Invalid document access settings") from exc
    department=department.strip()
    if not department:raise HTTPException(422,"Department or category is required")
    ext=Path(file.filename or "").suffix.lower()
    if ext not in {".pdf",".docx",".txt",".md"}: raise HTTPException(415,"Only PDF, DOCX, TXT, and MD files are supported")
    raw=await file.read()
    if len(raw)>25*1024*1024: raise HTTPException(413,"Maximum upload size is 25 MB")
    digest=hashlib.sha256(raw).hexdigest()
    existing=await db.scalar(select(Document).where(Document.workspace_id==user.workspace_id,Document.content_hash==digest,Document.freshness_status!=Freshness.DELETED))
    if existing and existing.ingestion_status==Ingestion.INDEXED and existing.freshness_status==Freshness.FRESH:
        existing.department=department;existing.description=description.strip() or None
        await apply_document_access(db,existing,access,user);await db.commit()
        return {"id":str(existing.id),"title":existing.title,"status":existing.freshness_status.value,"version":f"v{existing.version}","unchanged":True}
    old=None
    if existing and existing.ingestion_status==Ingestion.PENDING and existing.freshness_status in {Freshness.STALE,Freshness.QUEUED,Freshness.PROCESSING,Freshness.RETRYING}:
        existing.department=department;existing.description=description.strip() or None
        await apply_document_access(db,existing,access,user);await db.commit()
        return {"id":str(existing.id),"title":existing.title,"status":existing.freshness_status.value,"version":f"v{existing.version}","queued":True,"unchanged":True}
    if existing:
        doc=existing;old_path=doc.storage_path
        path=Path(settings.upload_dir)/f"{uuid.uuid4()}{ext}";path.write_bytes(raw)
        stat=path.stat();doc.storage_path=str(path);doc.file_type=ext[1:];doc.content_hash=digest;doc.version+=1;doc.department=department;doc.description=description.strip() or None
        await apply_document_access(db,doc,access,user)
        doc.source_last_modified_at=datetime.fromtimestamp(stat.st_mtime,timezone.utc);doc.storage_mtime_ns=stat.st_mtime_ns;doc.storage_size=stat.st_size
        await enqueue_document(db,doc,old_storage_path=old_path,force=True)
        db.add(AuditLog(user_id=user.id,action="RETRY_INDEX",resource=doc.title,status="SUCCESS",details={"content_hash":digest}))
    else:
        old=await db.scalar(select(Document).where(Document.workspace_id==user.workspace_id,Document.title==Path(file.filename or "document").name,Document.freshness_status!=Freshness.DELETED))
        path=Path(settings.upload_dir)/f"{uuid.uuid4()}{ext}";path.write_bytes(raw);stat=path.stat()
        doc=Document(workspace_id=user.workspace_id,external_document_id=f"upload:{file.filename}",source="upload",title=Path(file.filename or "document").name,description=description.strip() or None,file_type=ext[1:],storage_path=str(path),content_hash=digest,version=(old.version+1 if old else 1),department=department,ingestion_status=Ingestion.PENDING,freshness_status=Freshness.STALE,source_last_modified_at=datetime.fromtimestamp(stat.st_mtime,timezone.utc),storage_mtime_ns=stat.st_mtime_ns,storage_size=stat.st_size)
        doc.access_type=access.access_type
        db.add(doc);await db.flush();await apply_document_access(db,doc,access,user)
        await enqueue_document(db,doc,old_storage_path=old.storage_path if old else None,supersedes_document_id=old.id if old else None)
        db.add(AuditLog(user_id=user.id,action="UPLOAD",resource=doc.title,status="SUCCESS",details={"content_hash":digest,"queued":True}))
    try:
        await db.commit()
    except Exception:
        await db.rollback();path.unlink(missing_ok=True);raise
    return {"id":str(doc.id),"title":doc.title,"department":doc.department,"status":doc.freshness_status.value,"version":f"v{doc.version}","content_hash":digest,"queued":True}

@app.get("/api/documents")
async def list_documents(db:AsyncSession=Depends(get_db),user:User=Depends(current_user)):
    await flag_stale(db)
    docs=(await db.scalars(select(Document).where(readable_document_predicate(user)).order_by(desc(Document.created_at)))).all()
    if user.role==UserRole.ADMIN:
        logger.debug("Knowledge Base list uid=%s role=%s workspace=%s workspace_docs=%d returned=%d",user.id,user.role.value,user.workspace_id,len(docs),len(docs))
        return [{"id":str(d.id),"title":d.title,"description":d.description,"file_type":d.file_type,"department":d.department,"access_type":d.access_type.value,"status":d.freshness_status.value,"freshness_status":d.freshness_status.value,"version":f"v{d.version}","indexed_version":d.indexed_version,"source":d.source,"content_hash":d.content_hash,"indexed_content_hash":d.indexed_content_hash,"chunk_count":d.chunk_count,"indexing_progress":d.indexing_progress,"indexing_failed_at":d.indexing_failed_at.isoformat() if d.indexing_failed_at else None,"indexing_error":d.indexing_error} for d in docs]
    logger.debug("Knowledge Base list uid=%s role=%s workspace=%s workspace_docs=%d returned=%d",user.id,user.role.value,user.workspace_id,len(docs),len(docs))
    return [{"id":str(d.id),"title":d.title,"description":d.description,"file_type":d.file_type,"department":d.department,"status":d.freshness_status.value,"version":f"v{d.version}"} for d in docs]

@app.get("/api/documents/{document_id}")
async def document_details(document_id:uuid.UUID,db:AsyncSession=Depends(get_db),user:User=Depends(current_user)):
    doc=await db.scalar(select(Document).where(Document.id==document_id,readable_document_predicate(user)))
    if not doc:raise HTTPException(404,"Document not found")
    if user.role==UserRole.ADMIN:
        return {"id":str(doc.id),"title":doc.title,"description":doc.description,"file_type":doc.file_type,"department":doc.department,"access_type":doc.access_type.value,"status":doc.freshness_status.value,"version":f"v{doc.version}","indexing_error":doc.indexing_error}
    return {"id":str(doc.id),"title":doc.title,"description":doc.description,"file_type":doc.file_type,"department":doc.department,"status":doc.freshness_status.value,"version":f"v{doc.version}"}

@app.get("/api/documents/{document_id}/file")
async def open_document_file(document_id:uuid.UUID,db:AsyncSession=Depends(get_db),user:User=Depends(current_user)):
    doc=await db.scalar(select(Document).where(Document.id==document_id,readable_document_predicate(user)))
    if not doc:raise HTTPException(404,"Document not found")
    if doc.source!="upload" or not doc.storage_path:raise HTTPException(404,"Uploaded source file is unavailable")
    if doc.file_type.lower()!="pdf":raise HTTPException(415,"In-browser preview is available for PDF files")
    path=Path(doc.storage_path)
    if not path.is_file():raise HTTPException(404,"Source file is unavailable")
    upload_root=Path(settings.upload_dir).resolve()
    try:path.resolve().relative_to(upload_root)
    except ValueError:raise HTTPException(404,"Source file is unavailable")
    return FileResponse(path,media_type="application/pdf",filename=doc.title,content_disposition_type="inline",headers={"X-Content-Type-Options":"nosniff","Cache-Control":"private, no-store"})

@app.delete("/api/documents/{document_id}")
async def delete_document(document_id:uuid.UUID,db:AsyncSession=Depends(get_db),user:User=Depends(admin_user)):
    doc=await db.scalar(select(Document).where(Document.id==document_id,Document.workspace_id==user.workspace_id))
    if not doc: raise HTTPException(404,"Document not found")
    title=doc.title;stored_path=doc.storage_path if doc.source=="upload" else None
    await db.execute(delete(CitationInteraction).where(CitationInteraction.citation_id.in_(select(MessageCitation.id).where(MessageCitation.document_id==doc.id))))
    await db.execute(delete(MessageCitation).where(MessageCitation.document_id==doc.id))
    await db.execute(delete(DocumentChunk).where(DocumentChunk.document_id==doc.id))
    await db.execute(delete(DocumentACL).where(DocumentACL.document_id==doc.id))
    db.add(AuditLog(user_id=user.id,action="DELETE",resource=title,status="SUCCESS"))
    await db.delete(doc);await db.commit()
    if stored_path:
        root=Path(settings.upload_dir).resolve();candidate=Path(stored_path).resolve()
        if candidate.is_relative_to(root):
            try:candidate.unlink(missing_ok=True)
            except OSError:pass
    return {"status":"DELETED"}

@app.patch("/api/documents/{document_id}")
async def update_document(document_id:uuid.UUID,body:DocumentUpdateBody,db:AsyncSession=Depends(get_db),user:User=Depends(admin_user)):
    doc=await db.scalar(select(Document).where(Document.id==document_id,Document.workspace_id==user.workspace_id))
    if not doc or doc.freshness_status==Freshness.DELETED:raise HTTPException(404,"Document not found")
    changes=body.model_dump(exclude_unset=True,exclude_none=True)
    if not changes:raise HTTPException(422,"Provide a title, department, or description to update")
    if "title" in changes:doc.title=changes["title"].strip()
    if "department" in changes:
        doc.department=changes["department"].strip()
    if "description" in changes:doc.description=changes["description"].strip() or None
    await db.execute(update(DocumentChunk).where(DocumentChunk.document_id==doc.id).values(department=doc.department))
    db.add(AuditLog(user_id=user.id,action="DOCUMENT_UPDATE",resource=doc.title,status="SUCCESS",details={"fields":list(changes)}))
    await db.commit()
    return {"id":str(doc.id),"title":doc.title,"description":doc.description,"department":doc.department,"access_type":doc.access_type.value,"version":f"v{doc.version}","status":doc.freshness_status.value}

@app.get("/api/documents/{document_id}/access")
async def document_access(document_id:uuid.UUID,db:AsyncSession=Depends(get_db),user:User=Depends(admin_user)):
    doc=await db.scalar(select(Document).where(Document.id==document_id,Document.workspace_id==user.workspace_id))
    if not doc or doc.freshness_status==Freshness.DELETED:raise HTTPException(404,"Document not found")
    rows=(await db.scalars(select(DocumentACL).where(DocumentACL.document_id==doc.id,DocumentACL.workspace_id==user.workspace_id,DocumentACL.can_read.is_(True)))).all()
    user_ids=[uuid.UUID(row.grantee_id) for row in rows if row.grantee_type=="USER"]
    selected=(await db.scalars(select(User).where(User.workspace_id==user.workspace_id,User.id.in_(user_ids)))).all() if user_ids else []
    role_ids=[uuid.UUID(row.grantee_id) for row in rows if row.grantee_type=="EMPLOYEE_ROLE"]
    selected_roles=(await db.scalars(select(EmployeeRole).where(EmployeeRole.workspace_id==user.workspace_id,EmployeeRole.id.in_(role_ids)))).all() if role_ids else []
    return {"document_id":str(doc.id),"access_type":doc.access_type.value,"employee_role_ids":[str(r.id) for r in selected_roles],"employee_roles":[{"id":str(r.id),"name":r.name} for r in selected_roles],"users":[{"id":str(target.id),"full_name":target.full_name,"email":target.email,"is_active":target.is_active} for target in selected]}

@app.put("/api/documents/{document_id}/access")
async def update_document_access(document_id:uuid.UUID,body:DocumentAccessBody,db:AsyncSession=Depends(get_db),user:User=Depends(admin_user)):
    doc=await db.scalar(select(Document).where(Document.id==document_id,Document.workspace_id==user.workspace_id).with_for_update())
    if not doc or doc.freshness_status==Freshness.DELETED:raise HTTPException(404,"Document not found")
    await apply_document_access(db,doc,body,user)
    db.add(AuditLog(user_id=user.id,action="DOCUMENT_ACCESS_UPDATE",resource=doc.title,status="SUCCESS",details={"access_type":body.access_type.value,"employee_role_ids":[str(role_id) for role_id in body.employee_role_ids],"user_count":len(body.user_ids)}))
    await db.commit()
    return {"document_id":str(doc.id),"access_type":doc.access_type.value,"employee_role_ids":[str(role_id) for role_id in body.employee_role_ids],"user_ids":[str(user_id) for user_id in body.user_ids]}

@app.put("/api/documents/{document_id}/file")
async def replace_document_file(document_id:uuid.UUID,file:UploadFile=File(...),db:AsyncSession=Depends(get_db),user:User=Depends(admin_user)):
    doc=await db.scalar(select(Document).where(Document.id==document_id,Document.workspace_id==user.workspace_id).with_for_update())
    if not doc or doc.freshness_status==Freshness.DELETED:raise HTTPException(404,"Document not found")
    if doc.source!="upload":raise HTTPException(409,"Only uploaded documents can be replaced here")
    ext=Path(file.filename or "").suffix.lower()
    if ext not in {".pdf",".docx",".txt",".md"}:raise HTTPException(415,"Only PDF, DOCX, TXT, and MD files are supported")
    raw=await file.read()
    if len(raw)>25*1024*1024:raise HTTPException(413,"Maximum upload size is 25 MB")
    path=Path(settings.upload_dir)/f"{uuid.uuid4()}{ext}"
    path.write_bytes(raw);old_path=doc.storage_path;stat=path.stat()
    doc.external_document_id=f"upload:{file.filename}";doc.file_type=ext[1:];doc.storage_path=str(path)
    doc.content_hash=hashlib.sha256(raw).hexdigest();doc.version+=1
    doc.source_last_modified_at=datetime.fromtimestamp(stat.st_mtime,timezone.utc);doc.storage_mtime_ns=stat.st_mtime_ns;doc.storage_size=stat.st_size
    await enqueue_document(db,doc,old_storage_path=old_path,force=True)
    db.add(AuditLog(user_id=user.id,action="DOCUMENT_REPLACE",resource=doc.title,status="SUCCESS",details={"version":doc.version,"content_hash":doc.content_hash,"queued":True}))
    try:await db.commit()
    except Exception:
        await db.rollback();path.unlink(missing_ok=True);raise
    return {"id":str(doc.id),"title":doc.title,"department":doc.department,"status":doc.freshness_status.value,"version":f"v{doc.version}","queued":True}

@app.post("/api/documents/{document_id}/reindex")
async def reindex_document(document_id:uuid.UUID,db:AsyncSession=Depends(get_db),user:User=Depends(admin_user)):
    doc=await db.scalar(select(Document).where(Document.id==document_id,Document.workspace_id==user.workspace_id).with_for_update())
    if not doc or doc.freshness_status==Freshness.DELETED:raise HTTPException(404,"Document not found")
    if doc.source!="upload" or not doc.storage_path:raise HTTPException(404,"Stored source file is unavailable")
    path=Path(doc.storage_path);upload_root=Path(settings.upload_dir).resolve()
    try:path.resolve().relative_to(upload_root)
    except ValueError:raise HTTPException(404,"Stored source file is unavailable")
    if not path.is_file():raise HTTPException(404,"Stored source file is unavailable")
    await enqueue_document(db,doc,force=True)
    db.add(AuditLog(user_id=user.id,action="REINDEX",resource=doc.title,status="SUCCESS",details={"queued":True,"version":doc.version}))
    await db.commit()
    return {"id":str(doc.id),"status":"STALE","queued":True,"version":f"v{doc.version}"}
@app.post("/api/feedback")
async def feedback(body:FeedbackBody,db:AsyncSession=Depends(get_db),user:User=Depends(current_user)):
    if body.rating not in {"HELPFUL","NOT_HELPFUL"}:raise HTTPException(422,"Invalid rating")
    msg=await db.get(Message,body.message_id)
    if not msg or not await db.scalar(select(Conversation.id).where(Conversation.id==msg.conversation_id,Conversation.user_id==user.id)):raise HTTPException(404,"Message not found")
    db.add(QueryFeedback(message_id=msg.id,user_id=user.id,rating=body.rating,reason=body.reason));await db.commit();return {"status":"recorded"}

@app.post("/api/escalations")
async def escalate(body:EscalationBody,db:AsyncSession=Depends(get_db),user:User=Depends(current_user)):
    msg=await db.get(Message,body.message_id)
    if not msg or not await db.scalar(select(Conversation.id).where(Conversation.id==msg.conversation_id,Conversation.user_id==user.id)):raise HTTPException(404,"Message not found")
    db.add(Escalation(user_id=user.id,message_id=msg.id,query=body.query[:10000]));await db.commit();return {"status":"OPEN"}

@app.post("/api/citations/{citation_id}/interaction")
async def citation_interaction(citation_id:uuid.UUID,event:str=Query(...,pattern="^(HOVER|CLICK|OPEN_DOCUMENT)$"),db:AsyncSession=Depends(get_db),user:User=Depends(current_user)):
    citation=await db.scalar(select(MessageCitation.id).join(Document,Document.id==MessageCitation.document_id).join(Message,Message.id==MessageCitation.message_id).join(Conversation,Conversation.id==Message.conversation_id).where(MessageCitation.id==citation_id,Conversation.user_id==user.id,readable_document_predicate(user)))
    if not citation:raise HTTPException(404,"Citation not found")
    db.add(CitationInteraction(user_id=user.id,citation_id=citation_id,event=event));await db.commit();return {"status":"recorded"}

@app.get("/api/admin/scorecard")
async def scorecard(db:AsyncSession=Depends(get_db),admin:User=Depends(admin_user)):
    return await analytics(db,admin,30)

@app.get("/api/admin/analytics")
async def admin_analytics(days:int=Query(30,ge=7,le=90),db:AsyncSession=Depends(get_db),admin:User=Depends(admin_user)):
    return await analytics(db,admin,days)

async def analytics(db:AsyncSession,admin:User,days:int):
    workspace=admin.workspace_id; now=datetime.now(timezone.utc); start=now-timedelta(days=days); active_since=now-timedelta(days=30)
    total_users=await db.scalar(select(func.count(User.id)).where(User.workspace_id==workspace)) or 0
    total_documents=await db.scalar(select(func.count(Document.id)).where(Document.workspace_id==workspace,Document.freshness_status!=Freshness.DELETED)) or 0
    status_rows=(await db.execute(select(Document.freshness_status,func.count(Document.id)).where(Document.workspace_id==workspace,Document.freshness_status!=Freshness.DELETED).group_by(Document.freshness_status))).all()
    status_counts={status.value:int(count) for status,count in status_rows}
    total_queries=await db.scalar(select(func.count(AuditLog.id)).join(User,User.id==AuditLog.user_id).where(User.workspace_id==workspace,AuditLog.action=="QUERY")) or 0
    outcomes=(await db.execute(select(QueryEvent.outcome,func.count(QueryEvent.id)).where(QueryEvent.workspace_id==workspace).group_by(QueryEvent.outcome))).all()
    outcome_counts={outcome:int(count) for outcome,count in outcomes}
    legacy_rows=(await db.execute(select(AuditLog.status,AuditLog.details).join(User,User.id==AuditLog.user_id).where(User.workspace_id==workspace,AuditLog.action=="QUERY",AuditLog.details["outcome"].as_string().is_(None)))).all()
    for status,details in legacy_rows:
        if status=="ERROR":outcome_counts["FAILED"]=outcome_counts.get("FAILED",0)+1
        elif int((details or {}).get("authorized_chunks",0) or 0)>0:
            outcome="ANSWERED" if int((details or {}).get("cited",0) or 0)>0 else "NO_ANSWER"
            outcome_counts[outcome]=outcome_counts.get(outcome,0)+1
        else:outcome_counts["NO_CONTEXT"]=outcome_counts.get("NO_CONTEXT",0)+1
    total_response=await db.scalar(select(func.avg(QueryEvent.response_ms)).where(QueryEvent.workspace_id==workspace))
    recent_query_rows=(await db.execute(select(func.date(AuditLog.created_at),func.count(AuditLog.id)).join(User,User.id==AuditLog.user_id).where(User.workspace_id==workspace,AuditLog.action=="QUERY",AuditLog.created_at>=start).group_by(func.date(AuditLog.created_at)).order_by(func.date(AuditLog.created_at)))).all()
    trend_map={str(day):int(count) for day,count in recent_query_rows}
    trend=[{"date":(start.date()+timedelta(days=i)).isoformat(),"count":trend_map.get((start.date()+timedelta(days=i)).isoformat(),0)} for i in range(days+1)]
    last_indexed=await db.scalar(select(func.max(Document.indexed_at)).where(Document.workspace_id==workspace,Document.freshness_status!=Freshness.DELETED))
    chunk_count_subq=select(DocumentChunk.document_id,func.count(DocumentChunk.id).label("chunks")).group_by(DocumentChunk.document_id).subquery()
    retrieval_count=func.count(DocumentRetrievalEvent.id).label("retrievals");document_chunk_count=func.coalesce(chunk_count_subq.c.chunks,0).label("chunks")
    usage_rows=(await db.execute(select(Document.id,Document.title,Document.freshness_status,Document.indexed_at,retrieval_count,document_chunk_count).outerjoin(DocumentRetrievalEvent,and_(DocumentRetrievalEvent.document_id==Document.id,DocumentRetrievalEvent.workspace_id==workspace)).outerjoin(chunk_count_subq,chunk_count_subq.c.document_id==Document.id).where(Document.workspace_id==workspace,Document.freshness_status!=Freshness.DELETED).group_by(Document.id,Document.title,Document.freshness_status,Document.indexed_at,chunk_count_subq.c.chunks).order_by(retrieval_count.desc(),Document.title).limit(10))).all()
    most_used=[{"id":str(row.id),"title":row.title,"retrievals":int(row.retrievals),"chunks":int(row.chunks),"status":row.freshness_status.value,"last_indexed_at":row.indexed_at.isoformat() if row.indexed_at else None} for row in usage_rows]
    attention_rows=(await db.scalars(select(Document).where(Document.workspace_id==workspace,Document.freshness_status.in_([Freshness.STALE,Freshness.QUEUED,Freshness.FAILED,Freshness.PROCESSING,Freshness.RETRYING])).order_by(Document.freshness_status,desc(Document.created_at)).limit(25))).all()
    attention=[{"id":str(doc.id),"title":doc.title,"status":doc.freshness_status.value,"indexing_error":doc.indexing_error,"last_indexed_at":doc.indexed_at.isoformat() if doc.indexed_at else None} for doc in attention_rows]
    failed_indexing=await db.scalar(select(func.count(AuditLog.id)).join(User,User.id==AuditLog.user_id).where(User.workspace_id==workspace,AuditLog.status=="ERROR",AuditLog.action.in_(["INDEX","REINDEX","DOCUMENT_REPLACE"]))) or 0
    active_users=await db.scalar(select(func.count(func.distinct(AuditLog.user_id))).join(User,User.id==AuditLog.user_id).where(User.workspace_id==workspace,AuditLog.action=="QUERY",AuditLog.created_at>=active_since)) or 0
    user_query_count=func.count(AuditLog.id).label("queries")
    user_query_rows=(await db.execute(select(User.id,User.full_name,User.email,user_query_count,func.max(AuditLog.created_at).label("last_active")).join(AuditLog,and_(AuditLog.user_id==User.id,AuditLog.action=="QUERY",AuditLog.created_at>=active_since)).where(User.workspace_id==workspace).group_by(User.id,User.full_name,User.email).order_by(user_query_count.desc()).limit(10))).all()
    most_active=[{"id":str(row.id),"name":row.full_name,"email":row.email,"queries":int(row.queries),"last_active":row.last_active.isoformat() if row.last_active else None} for row in user_query_rows]
    recent_rows=(await db.execute(select(AuditLog.action,AuditLog.status,AuditLog.resource,AuditLog.created_at,User.full_name).join(User,User.id==AuditLog.user_id).where(User.workspace_id==workspace,AuditLog.action.in_(["QUERY","LOGIN","UPLOAD","INDEX","REINDEX","DOCUMENT_REPLACE","DOCUMENT_UPDATE","DOCUMENT_ACCESS_UPDATE","DELETE"])).order_by(desc(AuditLog.created_at)).limit(12))).all()
    recent_activity=[{"action":"Assistant query" if row.action=="QUERY" else row.action.replace("_"," ").title(),"status":row.status,"resource":row.resource if row.action!="QUERY" else "Private assistant activity","user":row.full_name,"created_at":row.created_at.isoformat()} for row in recent_rows]
    avg_ms=round(float(total_response or 0),1)
    processing_documents=sum(status_counts.get(status,0) for status in ("PROCESSING","QUEUED","RETRYING"))
    return {"period_days":days,"overview":{"total_users":total_users,"total_documents":total_documents,"total_queries":total_queries,"fresh_documents":status_counts.get("FRESH",0),"processing_documents":processing_documents,"stale_documents":status_counts.get("STALE",0),"failed_documents":status_counts.get("FAILED",0)},"usage":{"total_queries":total_queries,"answered":outcome_counts.get("ANSWERED",0),"no_relevant_answer":outcome_counts.get("NO_CONTEXT",0)+outcome_counts.get("NO_ANSWER",0),"failed_requests":outcome_counts.get("FAILED",0),"average_response_ms":avg_ms,"trend":trend},"knowledge":{"status_counts":status_counts,"documents_requiring_attention":attention,"failed_indexing_jobs":failed_indexing,"last_indexed_at":last_indexed.isoformat() if last_indexed else None},"documents":{"most_used":most_used},"users":{"active_users_30d":active_users,"most_active":most_active},"recent_activity":recent_activity,"rag":{"retrieval_requests":total_queries,"with_relevant_context":outcome_counts.get("ANSWERED",0)+outcome_counts.get("NO_ANSWER",0),"without_relevant_context":outcome_counts.get("NO_CONTEXT",0),"failed_requests":outcome_counts.get("FAILED",0),"average_response_ms":avg_ms}}

@app.get("/api/admin/audit")
async def audit(limit:int=Query(100,ge=1,le=500),db:AsyncSession=Depends(get_db),_:User=Depends(admin_user)):
    logs=(await db.scalars(select(AuditLog).join(User,User.id==AuditLog.user_id).where(User.workspace_id==_.workspace_id).order_by(desc(AuditLog.created_at)).limit(limit))).all()
    return [{"id":str(x.id),"action":x.action,"resource":x.resource,"status":x.status,"details":x.details,"created_at":x.created_at.isoformat()} for x in logs]

@app.get("/api/admin/escalations")
async def escalations(db:AsyncSession=Depends(get_db),_:User=Depends(admin_user)):
    rows=(await db.scalars(select(Escalation).where(Escalation.status=="OPEN").order_by(desc(Escalation.created_at)))).all()
    return [{"id":str(x.id),"user_id":str(x.user_id),"message_id":str(x.message_id),"query":x.query,"created_at":x.created_at.isoformat()} for x in rows]

@app.get("/api/admin/users")
async def users(db:AsyncSession=Depends(get_db),admin:User=Depends(admin_user)):
    conversation_count=select(func.count(Conversation.id)).where(Conversation.user_id==User.id).correlate(User).scalar_subquery()
    question_count=select(func.count(Message.id)).join(Conversation,Conversation.id==Message.conversation_id).where(Conversation.user_id==User.id,Message.role=="user").correlate(User).scalar_subquery()
    rows=(await db.execute(select(User,conversation_count,question_count).where(User.workspace_id==admin.workspace_id).order_by(User.email))).all()
    return [{**safe_user(u),"conversation_count":int(conversations),"question_count":int(questions)} for u,conversations,questions in rows]

@app.post("/api/admin/users",status_code=201)
async def create_employee(body:AdminEmployeeCreateBody,db:AsyncSession=Depends(get_db),admin:User=Depends(admin_user)):
    email=str(body.email).strip().lower()
    if await db.scalar(select(User.id).where(func.lower(User.email)==email)):
        raise HTTPException(409,"An employee account with this work email already exists")
    if body.system_permission==SystemPermission.ADMIN:
        employee_role=await db.scalar(select(EmployeeRole).where(EmployeeRole.workspace_id==admin.workspace_id,EmployeeRole.name=="ADMIN",EmployeeRole.is_active.is_(True)))
        if body.employee_role_id and (not employee_role or body.employee_role_id!=employee_role.id):raise HTTPException(422,"ADMIN system permission requires the ADMIN employee role")
    else:
        employee_role=await db.scalar(select(EmployeeRole).where(EmployeeRole.id==body.employee_role_id,EmployeeRole.workspace_id==admin.workspace_id,EmployeeRole.is_active.is_(True))) if body.employee_role_id else await db.scalar(select(EmployeeRole).where(EmployeeRole.workspace_id==admin.workspace_id,EmployeeRole.name=="Unassigned",EmployeeRole.is_active.is_(True)))
    if not employee_role:raise HTTPException(422,"Select an active employee role in this workspace")
    user=User(workspace_id=admin.workspace_id,employee_role_id=employee_role.id,email=email,hashed_password=hash_password(body.password),full_name=body.full_name,role=UserRole.ADMIN if body.system_permission==SystemPermission.ADMIN else UserRole.USER,department="General",is_active=body.is_active,must_change_password=True)
    db.add(user)
    try:
        await db.flush()
        db.add(AuditLog(user_id=admin.id,action="EMPLOYEE_CREATE",resource=str(user.id),status="SUCCESS",details={"email":email,"system_permission":body.system_permission.value,"employee_role_id":str(employee_role.id),"is_active":body.is_active,"must_change_password":True}))
        await db.commit();await db.refresh(user)
    except IntegrityError:
        await db.rollback();raise HTTPException(409,"An employee account with this work email already exists")
    return safe_user(user)

@app.patch("/api/admin/users/{user_id}")
async def update_user(user_id:uuid.UUID,body:AdminUserUpdateBody,db:AsyncSession=Depends(get_db),admin:User=Depends(admin_user)):
    u=await db.scalar(select(User).where(User.id==user_id,User.workspace_id==admin.workspace_id).with_for_update(of=User))
    if not u:raise HTTPException(404,"User not found")
    changes=body.model_dump(exclude_unset=True,exclude_none=True)
    if not changes:raise HTTPException(422,"Provide a name, system permission, employee role, or account status")
    new_system=changes.get("system_permission")
    removing_admin=u.role==UserRole.ADMIN and u.is_active and ((new_system==SystemPermission.EMPLOYEE) or changes.get("is_active") is False)
    if removing_admin:
        active_admins=(await db.scalars(select(User.id).where(User.workspace_id==admin.workspace_id,User.role==UserRole.ADMIN,User.is_active.is_(True)).with_for_update())).all()
        if len(active_admins)<=1:raise HTTPException(409,"The last active administrator cannot be demoted or disabled")
    if new_system is not None:
        u.role=UserRole.ADMIN if new_system==SystemPermission.ADMIN else UserRole.USER
        if new_system==SystemPermission.ADMIN:
            admin_employee_role=await db.scalar(select(EmployeeRole).where(EmployeeRole.workspace_id==admin.workspace_id,EmployeeRole.name=="ADMIN",EmployeeRole.is_active.is_(True)))
            if not admin_employee_role:raise HTTPException(409,"The ADMIN employee role is unavailable")
            u.employee_role_id=admin_employee_role.id
        elif u.role==UserRole.USER and u.employee_role and u.employee_role.name=="ADMIN":
            unassigned=await db.scalar(select(EmployeeRole).where(EmployeeRole.workspace_id==admin.workspace_id,EmployeeRole.name=="Unassigned",EmployeeRole.is_active.is_(True)))
            u.employee_role_id=unassigned.id if unassigned else None
    if "employee_role_id" in changes:
        employee_role=await db.scalar(select(EmployeeRole).where(EmployeeRole.id==changes["employee_role_id"],EmployeeRole.workspace_id==admin.workspace_id,EmployeeRole.is_active.is_(True)))
        if not employee_role:raise HTTPException(422,"Employee role must be active and belong to this workspace")
        if u.role==UserRole.ADMIN and employee_role.name!="ADMIN":raise HTTPException(422,"Administrators must keep the ADMIN employee role")
        u.employee_role_id=employee_role.id
    if "full_name" in changes:u.full_name=changes["full_name"]
    if "is_active" in changes:u.is_active=changes["is_active"]
    u.updated_at=datetime.now(timezone.utc)
    audit_changes={key:(value.value if isinstance(value,SystemPermission) else str(value) if isinstance(value,uuid.UUID) else value) for key,value in changes.items()}
    db.add(AuditLog(user_id=admin.id,action="USER_UPDATE",resource=str(u.id),status="SUCCESS",details=audit_changes));await db.commit();await db.refresh(u)
    return safe_user(u)

@app.post("/api/admin/users/{user_id}/reset-password")
async def admin_reset_password(user_id:uuid.UUID,body:AdminPasswordResetBody,db:AsyncSession=Depends(get_db),admin:User=Depends(admin_user)):
    u=await db.scalar(select(User).where(User.id==user_id,User.workspace_id==admin.workspace_id).with_for_update(of=User))
    if not u:raise HTTPException(404,"Employee account not found")
    u.hashed_password=hash_password(body.temporary_password)
    u.must_change_password=True
    u.auth_version+=1
    u.updated_at=datetime.now(timezone.utc)
    db.add(AuditLog(user_id=admin.id,action="EMPLOYEE_PASSWORD_RESET",resource=str(u.id),status="SUCCESS",details={"must_change_password":True}))
    await db.commit()
    return {"message":"Temporary password set. The employee must change it after signing in.","must_change_password":True}

@app.get("/api/admin/employee-roles")
async def list_employee_roles(db:AsyncSession=Depends(get_db),admin:User=Depends(admin_user)):
    rows=(await db.scalars(select(EmployeeRole).where(EmployeeRole.workspace_id==admin.workspace_id).order_by(EmployeeRole.name))).all()
    return [{"id":str(r.id),"name":r.name,"description":r.description,"is_active":r.is_active,"created_at":r.created_at.isoformat() if r.created_at else None,"updated_at":r.updated_at.isoformat() if r.updated_at else None} for r in rows]

@app.post("/api/admin/employee-roles",status_code=201)
async def create_employee_role(body:EmployeeRoleCreateBody,db:AsyncSession=Depends(get_db),admin:User=Depends(admin_user)):
    role=EmployeeRole(workspace_id=admin.workspace_id,name=body.name,description=body.description,is_active=True)
    db.add(role)
    try:
        await db.flush();db.add(AuditLog(user_id=admin.id,action="EMPLOYEE_ROLE_CREATE",resource=role.name,status="SUCCESS"));await db.commit()
    except IntegrityError:
        await db.rollback();raise HTTPException(409,"An employee role with that name already exists")
    return {"id":str(role.id),"name":role.name,"description":role.description,"is_active":role.is_active}

@app.patch("/api/admin/employee-roles/{role_id}")
async def update_employee_role(role_id:uuid.UUID,body:EmployeeRoleUpdateBody,db:AsyncSession=Depends(get_db),admin:User=Depends(admin_user)):
    role=await db.scalar(select(EmployeeRole).where(EmployeeRole.id==role_id,EmployeeRole.workspace_id==admin.workspace_id).with_for_update())
    if not role:raise HTTPException(404,"Employee role not found")
    changes=body.model_dump(exclude_unset=True)
    if not changes:raise HTTPException(422,"Provide a role name, description, or active status")
    if role.name=="ADMIN" and (changes.get("name",role.name)!="ADMIN" or changes.get("is_active") is False):raise HTTPException(409,"The ADMIN employee role cannot be renamed or deactivated")
    if changes.get("is_active") is False:
        assigned=await db.scalar(select(func.count(User.id)).where(User.workspace_id==admin.workspace_id,User.employee_role_id==role.id,User.is_active.is_(True)))
        granted=await db.scalar(select(func.count(DocumentACL.id)).where(DocumentACL.workspace_id==admin.workspace_id,DocumentACL.grantee_type=="EMPLOYEE_ROLE",DocumentACL.grantee_id==str(role.id)))
        if assigned or granted:raise HTTPException(409,"This role is assigned to active users or document access rules; reassign/remove those first")
    if "name" in changes:role.name=changes["name"]
    if "description" in changes:role.description=changes["description"]
    if "is_active" in changes:role.is_active=changes["is_active"]
    role.updated_at=datetime.now(timezone.utc)
    try:
        await db.flush();db.add(AuditLog(user_id=admin.id,action="EMPLOYEE_ROLE_UPDATE",resource=role.name,status="SUCCESS",details={k:(str(v) if isinstance(v,uuid.UUID) else v) for k,v in changes.items()}));await db.commit()
    except IntegrityError:
        await db.rollback();raise HTTPException(409,"An employee role with that name already exists")
    return {"id":str(role.id),"name":role.name,"description":role.description,"is_active":role.is_active}

@app.get("/api/admin/users/{user_id}")
async def user_details(user_id:uuid.UUID,db:AsyncSession=Depends(get_db),admin:User=Depends(admin_user)):
    conversation_count=select(func.count(Conversation.id)).where(Conversation.user_id==User.id).correlate(User).scalar_subquery()
    question_count=select(func.count(Message.id)).join(Conversation,Conversation.id==Message.conversation_id).where(Conversation.user_id==User.id,Message.role=="user").correlate(User).scalar_subquery()
    row=(await db.execute(select(User,conversation_count,question_count).where(User.id==user_id,User.workspace_id==admin.workspace_id))).first()
    if not row:raise HTTPException(404,"User not found")
    u,conversations,questions=row
    return {**safe_user(u),"conversation_count":int(conversations),"question_count":int(questions)}

@app.patch("/api/admin/users/{user_id}/status")
async def update_user_status(user_id:uuid.UUID,body:AdminUserStatusBody,db:AsyncSession=Depends(get_db),admin:User=Depends(admin_user)):
    return await update_user(user_id,AdminUserUpdateBody(is_active=body.is_active),db,admin)
