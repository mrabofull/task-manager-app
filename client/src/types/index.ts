export interface Task {
  id: string;
  title: string;
  description?: string;
  dueDate?: string;
  done: boolean;
  createdAt: string;
  updatedAt: string;
}

export interface User {
  email: string;
}
