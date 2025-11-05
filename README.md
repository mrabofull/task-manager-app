# Task Manager Full-Stack Application

A production-ready task management application with advanced security features, dual lockout mechanisms, IP allowlist, email verification, and task CRUD operations.

## 🚀 Live Demo

- **Frontend**: https://task-manager-app-cj3n.onrender.com/
- **Backend API**: https://taskmanager-api-dfgc.onrender.com/api

## 🚀 Quick Start

### Prerequisites

- Node.js and npm
- PostgreSQL
- Git

### Setup Instructions

1. **Clone the repository**

```bash
git clone [your-repo-url]
cd task-manager-app
```

2. **Backend Setup**

```bash
cd server
npm install
```

Create `.env` file in server directory:

```env
DATABASE_URL=postgresql://...  # For production (Render)
DB_HOST=127.0.0.1
DB_PORT=5432
DB_USERNAME=postgres1
DB_PASSWORD=TestPassword1
DB_NAME=tasks
JWT_SECRET=sdf9w34rFJ3Fasd1sdff09sDFJ9Sdf6f4sDFJsdjfsdFsfs
JWT_EXPIRATION=15m
BCRYPT_SALT_ROUNDS=10
JWT_REFRESH_SECRET=sdf9w34rFJ3Fasd1sdff09sDFJ9Sdf6f4sDFJsdjfsdFszf
MAX_USER_SESSIONS=3
JWT_REFRESH_EXPIRATION=7d
PORT=3000
# Email settings (Gmail)
SMTP_HOST=smtp.gmail.com
SMTP_PORT=587
SMTP_USER=example@example.com
SMTP_PASSWORD=safasdgfssds
SMTP_FROM_NAME=example
NODE_ENV=development # development || production
ADMIN_EMAIL=example@example.com
```

`.env.production` in fontend directory:
VITE_API_URL=api://... # For production (Render)

Start the backend:

```bash
npm run start:dev
```

3. **Frontend Setup**

```bash
cd ../client
npm install
npm run dev
```

4. **Access the application**

- Frontend: http://localhost:5173
- Backend API: http://localhost:3000/api
- Dev Mailbox: http://localhost:3000/api/auth/dev/mailbox

## ✨ Features Implemented

### Core Features (All Completed ✅)

- **User Authentication**

  - Sign up with email verification (6-digit code, 15-minute expiry)
  - Email verification required on every login (2FA-like security)
  - JWT with HttpOnly cookies (15-min access + 7-day refresh tokens)
  - Automatic token refresh on API calls
  - Secure logout with cookie clearing

- **Task Management**

  - Full CRUD operations (Create, Read, Update, Delete)
  - User-isolated data (each user sees only their tasks)
  - Search by title/description
  - Filter by completion status (All/Active/Completed)
  - Pagination (10 tasks per page)
  - Due dates with date/time picker
  - Mobile-responsive task interface

### Advanced Security Features ✅

- **Dual Lockout System**

  - Account lockout: 3 failed attempts = 2-minute lock (per user)
  - IP lockout: 10 failed attempts from any IP = 15-minute lock
  - Failed attempt counters reset after 2 hours of inactivity
  - Lockout timers shown to users

- **IP Allowlist (Production Mode)**

  - Database-persisted IP restrictions
  - Admin API endpoints for management
  - Bypassed in development mode for testing
  - Tamper-resistant with server-side validation

- **Session Management**

  - Maximum 3 concurrent sessions per user
  - Oldest session auto-revoked on new login
  - Session tracking in database

- **Additional Security**
  - Rate limiting: 10 requests/minute per endpoint
  - CSRF protection with SameSite cookies
  - Input validation with Zod (frontend) and class-validator (backend)
  - SQL injection prevention via TypeORM parameterized queries
  - XSS prevention with React's built-in escaping
  - Generic error messages to prevent user enumeration

### UI/UX Features

- Responsive design (mobile-friendly)
- Real-time form validation with inline errors
- Toast notifications for all actions
- Loading states and skeletons
- Empty states with helpful messages

## 🛠 Technical Stack

### Backend

- **Framework**: NestJS with TypeScript
- **Database**: PostgreSQL with TypeORM
- **Authentication**: JWT with HttpOnly cookies
- **Validation**: class-validator and class-transformer and ValidationPipe
- **Security**: bcrypt, @nestjs/throttler for rate limiting, CORS
- **Email**: Dual mode (SMTP for production, file-based for dev)
- **Deployment**: Render (with auto-deploy from GitHub)

### Frontend

- **Framework**: React 19 with TypeScript
- **Build Tool**: Vite
- **Styling**: Tailwind CSS + Shadcn/ui components
- **State Management**: Zustand (chosen for minimal boilerplate and TypeScript support)
- **Forms**: React Hook Form + Zod validation
- **Routing**: React Router v6
- **HTTP Client**: Axios with interceptors for auto-refresh
- **Notifications**: Sonner for toast messages
- **Deployment**: Render (with auto-deploy from GitHub)

### Database

- **SQL**: PostgreSQL
- **Deployment**: Render

## 📁 Project Structure

```
task-manager-app/
├── server/                     # Backend (NestJS)
│   ├── src/
│   │   ├── auth/               # Authentication module
│   │   │   ├── entities/       # User, UserSession, LoginAttempt, IpAllowlist, VerificationCode
│   │   │   ├── services/       # MailService, verification logic
│   │   │   ├── guards/         # JWT auth guard
│   │   │   └── strategies/     # JWT and refresh token strategies
│   │   ├── tasks/              # Tasks CRUD module
│   │   │   └── entities/       # Task entity
        ├── users/
            └── entities/
│   │   └── main.ts             # App entry (CORS, global pipes, etc.)
│   └── dist/                   # Compiled backend JavaScript
│
├── client/                     # Frontend (React + TypeScript + Vite)
│   ├── src/
│   │   ├── components/         # Auth, Tasks, UI components
│   │   ├── pages/              # Login, Signup, Verify, Tasks pages
│   │   ├── lib/                # API client with interceptors (axios)
│   │   └── hooks/              # Custom React hooks
│   └── dist/                   # Production frontend build
│
└── README.md

```

## 🔐 API Endpoints

| Method | Endpoint                           | Description              | Rate Limit |
| ------ | ---------------------------------- | ------------------------ | ---------- |
| POST   | `/api/auth/signup`                 | Register new user        | -          |
| POST   | `/api/auth/verify`                 | Verify email with code   | 5/min      |
| POST   | `/api/auth/login`                  | Login user               | 10/min     |
| POST   | `/api/auth/logout`                 | Logout user              | -          |
| POST   | `/api/auth/refresh`                | Refresh JWT token        | -          |
| POST   | `/api/auth/resend-verification`    | Resend verification code | 3/5min     |
| GET    | `/api/tasks`                       | Get user's tasks         | -          |
| POST   | `/api/tasks`                       | Create new task          | -          |
| PATCH  | `/api/tasks/:id`                   | Update task              | -          |
| DELETE | `/api/tasks/:id`                   | Delete task              | -          |
| GET    | `/api/auth/dev/mailbox`            | View sent emails         | -          |
| GET    | `/api/auth/admin/ip-allowlist`     | List allowed IPs         | -          |
| POST   | `/api/auth/admin/ip-allowlist`     | Add IP to allowlist      | -          |
| DELETE | `/api/auth/admin/ip-allowlist/:id` | Remove IP                | -          |

**.env example is found inside of the server folder**

## 💡 Architecture Decisions

### State Management Choice (Zustand)

I chose Zustand over Redux/Context API because:

- **Minimal boilerplate**: Quick setup for a time-constrained project
- **TypeScript first**: Excellent type inference without extra configuration
- **Persistence**: Built-in middleware for localStorage persistence
- **Bundle size**: Only 8KB vs Redux Toolkit's 40KB+
- **Developer experience**: Simple API that's easy to understand and debug

### Security Approach

- **Dual lockout** Both per-account and per-IP protection
- **HttpOnly cookies** for JWT storage (prevents XSS attacks)
- **Refresh tokens** Short-lived access tokens (15 min) with long refresh (7 days)
- **Rate limiting** on authentication endpoints
- **Bcrypt** with 10 salt rounds for password hashing
- **IP allowlist** Production-only restriction with admin management
- **Input validation** at both frontend (Zod) and backend (class-validator)

## ⏱ Development Timeline

- Backend setup and authentication: ~15 hours
- Frontend setup and auth pages: ~12 hours
- Task CRUD implementation: ~4 hours
- Bug fixes and polish: ~6 hours
- Documentation: ~1 hour
- Deployment & troubleshooting: 2 hours
- **Total: ~40 hours**

## 🚧 Future Improvements (with more time)

- **Testing**: Unit tests for services, integration tests for API
- **Features**: Task categories, due date reminders, task sharing
- **Security**: OAuth2 integration (Google, GitHub), Audit trail for all actions
- **Performance**: Redis caching, database indexing optimization
- **DevOps**: Docker containers, CI/CD pipeline, monitoring
- **UX**: Drag-and-drop task reordering, dark mode

## 🐛 Known Issues

- None at time of submission

## Author

Mohamed Abo Full
