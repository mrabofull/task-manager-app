import type { User } from "@/types";
import { create } from "zustand";
import { persist } from "zustand/middleware";

interface AuthState {
  user: User | null;
  isAuthenticated: boolean;
  verificationEmail: string | null;
  verificationExpiresAt: string | null;
  setUser: (user: User | null) => void;
  setVerificationEmail: (email: string | null) => void;
  setVerificationExpiry: (expiresAt: string | null) => void;
  logout: () => void;
}

export const useAuthStore = create<AuthState>()(
  persist(
    (set) => ({
      user: null,
      isAuthenticated: false,
      verificationEmail: null,
      verificationExpiresAt: null,
      setUser: (user) => set({ user, isAuthenticated: !!user }),
      setVerificationEmail: (email) => set({ verificationEmail: email }),
      setVerificationExpiry: (expiresAt) =>
        set({ verificationExpiresAt: expiresAt }),
      logout: () =>
        set({
          user: null,
          isAuthenticated: false,
          verificationEmail: null,
          verificationExpiresAt: null,
        }),
    }),
    {
      name: "auth-storage",
    }
  )
);
