import axios from "axios";
import { useAuthStore } from "@/stores/authStore";
import type { User } from "@/types";

const API_BASE = "http://localhost:3000/api";

export const api = axios.create({
  baseURL: API_BASE,
  withCredentials: true, // to include cookies when sending requests
});

let isRefreshing = false;
let failedQueue: any[] = [];

const processQueue = (error: any, token: string | null = null) => {
  failedQueue.forEach((prom) => {
    if (error) {
      prom.reject(error);
    } else {
      prom.resolve(token);
    }
  });
  failedQueue = [];
};

// to check every response before the code sees it
// Response interceptor for token refresh
api.interceptors.response.use(
  (res) => res.data,
  async (err) => {
    const originalRequest = err.config;
    const isAuthEndpoint = originalRequest.url?.includes("/auth/");
    if (
      err.response?.status === 401 &&
      !originalRequest._retry &&
      !isAuthEndpoint
    ) {
      if (isRefreshing) {
        return new Promise((resolve, reject) => {
          failedQueue.push({ resolve, reject });
        })
          .then(() => api(originalRequest))
          .catch((err) => Promise.reject(err));
      }

      originalRequest._retry = true;
      isRefreshing = true;

      try {
        await api.post("/auth/refresh");
        processQueue(null);
        return api(originalRequest);
      } catch (refreshError) {
        processQueue(refreshError, null);
        // Logout user if refresh fails
        useAuthStore.getState().logout();
        window.location.href = "/login";
        return Promise.reject(refreshError);
      } finally {
        isRefreshing = false;
      }
    }

    const message = err.response?.data?.message || "Something went wrong";
    return Promise.reject(new Error(message));
  }
);

interface TasksResponse {
  data: any[];
  meta: {
    total: number;
    page: number;
    limit: number;
    totalPages: number;
    hasNextPage: boolean;
    hasPreviousPage: boolean;
  };
}

interface AuthResponse {
  message: string;
  expiresAt?: string;
  user?: User;
  email?: string;
  requiresVerification?: boolean;
}

export const authAPI = {
  signup: (data: {
    name: string;
    email: string;
    password: string;
  }): Promise<AuthResponse> => api.post("/auth/signup", data),
  verify: (data: { email: string; code: string }): Promise<AuthResponse> =>
    api.post("/auth/verify", data),
  resendCode: (data: { email: string }): Promise<AuthResponse> =>
    api.post("/auth/resend-verification", data),
  login: (data: { email: string; password: string }): Promise<AuthResponse> =>
    api.post("/auth/login", data),
  logout: (): Promise<void> => api.post("/auth/logout"),
};

export const tasksAPI = {
  getAll: (params?: any): Promise<TasksResponse> =>
    api.get<any, TasksResponse>("/tasks", { params }),
  create: (data: any) => api.post("/tasks", data),
  update: (id: string, data: any) => api.patch(`/tasks/${id}`, data),
  delete: (id: string) => api.delete(`/tasks/${id}`),
};
