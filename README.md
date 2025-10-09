# Task Manager Full-Stack Application

A production-ready task management application with secure authentication, email verification, and comprehensive task CRUD operations.

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
DB_HOST=localhost
DB_PORT=5432
DB_USERNAME=postgres
DB_PASSWORD=yourpassword
DB_NAME=taskmanager
JWT_SECRET=your-secure-secret-key
JWT_EXPIRATION=24h
```

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

  - Sign up with email and password
  - Email verification with 6-digit code (15-minute expiry)
  - Login with JWT stored in HttpOnly cookies
  - Account lockout after 3 failed attempts (2 minutes)
  - Logout functionality

- **Task Management**

  - Create tasks with title, optional description, and due date
  - View all tasks (paginated, 10 per page)
  - Update task details and completion status
  - Delete tasks
  - Search tasks by title/description
  - Filter by completion status (All/Active/Completed)
  - User-isolated data (each user sees only their tasks)

- **Security Features**
  - Password hashing with bcrypt (10 rounds)
  - Rate limiting on auth endpoints
  - Input validation and sanitization
  - CORS configuration for production
  - Session persistence across refresh
  - Automatic logout on token expiration

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
- **Security**: bcrypt, @nestjs/throttler for rate limiting
- **Email**: Mock email service with JSON file persistence

### Frontend

- **Framework**: React 19 with TypeScript
- **Build Tool**: Vite
- **Styling**: Tailwind CSS + Shadcn/ui components
- **State Management**: Zustand (chosen for minimal boilerplate and TypeScript support)
- **Forms**: React Hook Form + Zod validation
- **Routing**: React Router v6
- **HTTP Client**: Axios with interceptors
- **Notifications**: Sonner

## 📁 Project Structure

```
task-manager-app/
├── server/                 # Backend NestJS application
│   ├── src/
│   │   ├── auth/          # Authentication module
│   │   ├── tasks/         # Tasks CRUD module
│   │   ├── users/         # User management module
│   │   └── main.ts        # Application entry point
│   └── .env               # Environment variables
│
├── client/                 # Frontend React application
│   ├── src/
│   │   ├── components/    # Reusable UI components
│   │   ├── pages/         # Route pages
│   │   ├── lib/           # API client and utilities
│   │   ├── stores/        # Zustand state stores
│   │   └── types/         # TypeScript type definitions
│   └── package.json
│
└── README.md
```

## 🔐 API Endpoints

| Method | Endpoint                        | Description              | Rate Limit |
| ------ | ------------------------------- | ------------------------ | ---------- |
| POST   | `/api/auth/signup`              | Register new user        | -          |
| POST   | `/api/auth/verify`              | Verify email with code   | 5/min      |
| POST   | `/api/auth/login`               | Login user               | 10/min     |
| POST   | `/api/auth/logout`              | Logout user              | -          |
| POST   | `/api/auth/resend-verification` | Resend verification code | 3/5min     |
| GET    | `/api/tasks`                    | Get user's tasks         | -          |
| POST   | `/api/tasks`                    | Create new task          | -          |
| PATCH  | `/api/tasks/:id`                | Update task              | -          |
| DELETE | `/api/tasks/:id`                | Delete task              | -          |
| GET    | `/api/auth/dev/mailbox`         | View sent emails         | -          |

## 💡 Architecture Decisions

### State Management Choice (Zustand)

I chose Zustand over Redux/Context API because:

- **Minimal boilerplate**: Quick setup for a time-constrained project
- **TypeScript first**: Excellent type inference without extra configuration
- **Persistence**: Built-in middleware for localStorage persistence
- **Bundle size**: Only 8KB vs Redux Toolkit's 40KB+
- **Developer experience**: Simple API that's easy to understand and debug

### Security Approach

- **HttpOnly cookies** for JWT storage (prevents XSS attacks)
- **Account lockout** per user (not IP) to prevent user enumeration
- **Rate limiting** on authentication endpoints
- **Bcrypt** with 10 salt rounds for password hashing
- **Input validation** at both frontend (Zod) and backend (class-validator)

## ⏱ Development Timeline

- Backend setup and authentication: ~6 hours
- Frontend setup and auth pages: ~6 hours
- Task CRUD implementation: ~4 hours
- Bug fixes and polish: ~2 hours
- Documentation: ~30 minutes
- **Total: ~18.5 hours**

## 🚧 Future Improvements (with more time)

- **Testing**: Unit tests for services, integration tests for API
- **Features**: Task categories, due date reminders, task sharing
- **Security**: Refresh token rotation, 2FA support
- **Performance**: Redis caching, database indexing optimization
- **DevOps**: Docker containers, CI/CD pipeline, monitoring
- **UX**: Drag-and-drop task reordering, dark mode

## 🐛 Known Issues

- None at time of submission

## 📝 Notes for Reviewers

- The email verification uses a mock service that saves to `mail-outbox.json`
- Check sent emails at: http://localhost:3000/api/auth/dev/mailbox
- Default pagination is 10 tasks per page
- Session expires after 24 hours (configurable via JWT_EXPIRATION)

## Author

Mohamed Abo Full
Submitted: October 9, 2025, 8:45 PM
