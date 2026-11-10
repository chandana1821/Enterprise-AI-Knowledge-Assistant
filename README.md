# 🤖 Knowbase

<p align="center">
  <strong>AI knowledge assistant for teams</strong><br />
  Ask questions in plain English and get answers grounded in company documents, with citations that link back to the source page.
</p>

<p align="center">
  <img alt="React 18" src="https://img.shields.io/badge/Frontend-React%2018-149eca?style=flat-square&logo=react&logoColor=white" />
  <img alt="TypeScript" src="https://img.shields.io/badge/Language-TypeScript-3178c6?style=flat-square&logo=typescript&logoColor=white" />
  <img alt="FastAPI" src="https://img.shields.io/badge/Backend-FastAPI-009688?style=flat-square&logo=fastapi&logoColor=white" />
  <img alt="PostgreSQL and pgvector" src="https://img.shields.io/badge/Database-PostgreSQL%20%2B%20pgvector-4169e1?style=flat-square&logo=postgresql&logoColor=white" />
  <img alt="Google Gemini" src="https://img.shields.io/badge/AI-Google%20Gemini-8e75b2?style=flat-square" />
  <img alt="Docker Compose" src="https://img.shields.io/badge/Local%20stack-Docker%20Compose-2496ed?style=flat-square&logo=docker&logoColor=white" />
</p>

> [!NOTE]
> **Project status:** actively developed. The repository runs locally with Docker Compose; it is not a production deployment package.

---

## 📚 Contents

- [Why Knowbase](#-why-knowbase)
- [Features](#-features)
- [Screenshots](#-screenshots)
- [How it works](#-how-it-works)
- [Technology stack](#-technology-stack)
- [Getting started](#-getting-started)
- [Project structure](#-project-structure)
- [Planned improvements](#-planned-improvements)
- [Author](#-author)
- [License](#-license)

## 💡 Why Knowbase

Company knowledge is often scattered across PDFs, handbooks, and policy documents. Finding a simple answer—such as “how many sick leave days do I get?”—can mean opening several files and skimming through them. Generic chatbots can make things up and do not know who is allowed to see each document.

Knowbase addresses three problems:

| Challenge | How Knowbase helps |
|---|---|
| Answers are hard to find | Natural-language Q&A over uploaded documents |
| AI can hallucinate | Answers come from retrieved passages with verified citations. If nothing relevant is found, the assistant says so. |
| Document access differs | Backend access rules for everyone, selected roles, or selected users are applied before text reaches the AI. |

## ✨ Features

| Feature | What it does |
|---|---|
| 💬 **Grounded Q&A with citations** | Shows document, page, and excerpt for sources; validates citations against retrieved passages. |
| 📄 **Document upload and indexing** | Processes PDF, DOCX, TXT, and Markdown files through a background worker with status, progress, and retries. |
| 🔐 **Access control** | Applies admin/user permissions, employee roles, and per-document access rules to both document listing and AI retrieval. |
| 🧑‍💼 **Admin tools** | Supports employee management, role assignment, password resets, and workspace analytics. |
| 🗂️ **Private history** | Keeps each user's conversations and search history visible only to that user. |
| 📝 **Feedback and escalation** | Provides thumbs-up/down feedback and escalation on answers. |
| 👁️ **PDF preview** | Opens authorized source documents in the browser. |

## 🖼️ Screenshots

<p align="center">
  <img src="docs/screenshots/sign-in.png" alt="Knowbase sign-in screen" width="48%" />
  <img src="docs/screenshots/assistant-admin.png" alt="Assistant workspace for an admin" width="48%" />
</p>

<p align="center">
  <img src="docs/screenshots/assistant-sources.png" alt="Assistant answer with source citations" width="65%" />
  <img src="docs/screenshots/knowledge-base-admin.png" alt="Admin knowledge base" width="32%" />
</p>

<details>
<summary>📷 View more screenshots</summary>
<br />

<p align="center">
  <img src="docs/screenshots/document-upload.png" alt="Document upload with access settings" width="48%" />
  <img src="docs/screenshots/analytics-overview.png" alt="Workspace analytics" width="48%" />
</p>

<p align="center">
  <img src="docs/screenshots/user-management.png" alt="User management" width="48%" />
  <img src="docs/screenshots/knowledge-base-user.png" alt="User knowledge base view" width="48%" />
</p>

<p align="center">
  <img src="docs/screenshots/pdf-preview.png" alt="PDF preview" width="48%" />
  <img src="docs/screenshots/profile.png" alt="Profile and private history" width="48%" />
</p>
</details>

## ⚙️ How it works

Knowbase uses a retrieval-augmented generation (RAG) pipeline with document access checks built in.

```mermaid
flowchart LR
    A[Admin uploads document] --> B[Indexing job queued]
    B --> C[Worker extracts and chunks text]
    C --> D[Gemini creates embeddings]
    D --> E[(PostgreSQL + pgvector)]

    F[User asks a question] --> G[Check user access]
    G --> H[Search permitted document chunks]
    E --> H
    H --> I[Gemini drafts an answer from retrieved passages]
    I --> J[Validate citations]
    J --> K[Show answer and sources]
```

### Document indexing

1. An admin uploads a file and chooses its access policy.
2. The API stores the file and queues an indexing job in PostgreSQL, allowing the upload request to return promptly.
3. A background worker extracts text, splits it into overlapping chunks (1,100 characters, with 140 characters of overlap), and generates embeddings with Gemini.
4. Vectors are stored in pgvector. When a document is replaced, its new version takes over only after indexing is ready.

### Question answering

1. The API determines which documents the user may access.
2. It runs vector similarity search only across those documents.
3. The most relevant passages and the question are sent to Gemini to draft an answer.
4. Citation references are checked against the retrieved passages. If no relevant evidence is found, the app returns a “no answer” response instead of guessing.

> [!IMPORTANT]
> **Authorization is enforced by the backend, not the UI.** The same access rule is used for document listing and retrieval, then checked again just before the prompt is built.

## 🧰 Technology stack

| Layer | Technologies |
|---|---|
| Frontend | React 18, TypeScript, Vite, Axios |
| Backend | Python 3.12, FastAPI, SQLAlchemy 2 (async), Pydantic |
| Database | PostgreSQL 16, pgvector |
| AI | Google Gemini for answers and embeddings |
| Document parsing | pypdf, python-docx |
| Authentication | JWT, bcrypt, role-based access |
| Infrastructure | Docker Compose |

## 🚀 Getting started

### Prerequisites

- Docker Desktop
- Node.js and npm
- A Google Gemini API key

### 1. Configure the backend

```bash
cp backend/.env.example backend/.env
```

Edit `backend/.env` and set `JWT_SECRET`, `GEMINI_API_KEY`, `ADMIN_EMAIL`, and `ADMIN_PASSWORD`.

### 2. Start the database and API

```bash
docker compose up -d --build
```

### 3. Create the first admin

```bash
docker compose exec api python -m app.seed
```

### 4. Run the frontend

```bash
npm ci
npm run dev
```

Open [http://localhost:5173](http://localhost:5173) and sign in with the admin account.

### Local service URLs

| Service | URL |
|---|---|
| Frontend | [http://localhost:5173](http://localhost:5173) |
| API documentation (Swagger) | [http://localhost:8000/docs](http://localhost:8000/docs) |
| API health check | [http://localhost:8000/health](http://localhost:8000/health) |

> [!TIP]
> Public sign-up is disabled by design. Admins create employee accounts from the **Users** page.

## 🗂️ Project structure

```text
.
├── src/                   # React app: chat, knowledge base, and admin UI
├── backend/app/
│   ├── main.py            # API routes
│   ├── rag.py             # Embeddings, retrieval, and answer generation
│   ├── indexing.py        # Background indexing queue and worker
│   ├── connectors.py      # PDF, DOCX, TXT, and Markdown extraction
│   ├── security.py        # JWT, password hashing, and access rules
│   └── models.py          # Database models
├── docs/screenshots/
└── docker-compose.yml
```

## 🧭 Planned improvements

- Automated tests, including end-to-end checks for permissions and retrieval
- Versioned database migrations (Alembic)
- Production deployment setup with managed secrets, TLS, and object storage
- Single sign-on (SSO) support

## 👤 Author

**[Anumula Chandana]** · [LinkedIn](https://www.linkedin.com/in/chandana1821/) · [Email](mailto:anumulachandana18@gmail.com)

## 📄 License

No license file is currently included. All rights reserved unless a license is added.
