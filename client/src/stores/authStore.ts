import { create } from "zustand";
import { persist } from "zustand/middleware";

interface AuthState {
  user: { email: string } | null;
  isAuthenticated: boolean;
  verificationEmail: string | null;
  setUser: (user: { email: string } | null) => void;
  setVerificationEmail: (email: string | null) => void;
  logout: () => void;
}

export const useAuthStore = create<AuthState>()(
  persist(
    (set) => ({
      user: null,
      isAuthenticated: false,
      verificationEmail: null,
      setUser: (user) => set({ user, isAuthenticated: !!user }),
      setVerificationEmail: (email) => set({ verificationEmail: email }),
      logout: () =>
        set({
          user: null,
          isAuthenticated: false,
          verificationEmail: null,
        }),
    }),
    {
      name: "auth-storage",
    }
  )
);
