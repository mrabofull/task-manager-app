import axios from "axios";

const API_BASE = "http://localhost:3000/api";

export const api = axios.create({
  baseURL: API_BASE,
  withCredentials: true, // to include cookies when sending requests
});

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

// to check every response before the code sees it
api.interceptors.response.use(
  (res) => res.data, // succ responeses
  (err) => {
    // errors
    if (err.response?.status === 401) {
      const authStorage = localStorage.getItem("auth-storage");
      if (authStorage) {
        const authState = JSON.parse(authStorage);
        authState.state.isAuthenticated = false;
        authState.state.user = null;
        localStorage.setItem("auth-storage", JSON.stringify(authState));
      }

      if (
        window.location.pathname !== "/login" &&
        window.location.pathname !== "/signup" &&
        window.location.pathname !== "/verify"
      ) {
        window.location.href = "/login";
      }

      const message = "Session expired. Please login again.";
      return Promise.reject(new Error(message));
    }
    const message = err.response?.data?.message || "Something went wrong";
    return Promise.reject(new Error(message));
  }
);

export const authAPI = {
  signup: (data: { email: string; password: string }) =>
    api.post("/auth/signup", data),
  verify: (data: { email: string; code: string }) =>
    api.post("/auth/verify", data),
  resendCode: (data: { email: string }) =>
    api.post("/auth/resend-verification", data),
  login: (data: { email: string; password: string }) =>
    api.post("/auth/login", data),
  logout: () => api.post("/auth/logout"),
};

export const tasksAPI = {
  getAll: (params?: any): Promise<TasksResponse> =>
    api.get<any, TasksResponse>("/tasks", { params }),
  create: (data: any) => api.post("/tasks", data),
  update: (id: string, data: any) => api.patch(`/tasks/${id}`, data),
  delete: (id: string) => api.delete(`/tasks/${id}`),
};
