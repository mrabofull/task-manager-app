import { z } from "zod";

export const signupSchema = z
  .object({
    name: z
      .string()
      .min(3, "Name must be at least 3 characters")
      .max(20, "Name must be at most 20 characters")
      .regex(/^[A-Za-z]+(?: [A-Za-z]+)*$/, "Enter a valid name"),
    email: z.string().email("Invalid email address"),
    password: z
      .string()
      .min(8, "Password must be at least 8 characters")
      .max(25, "Password must be at most 25 characters")
      .regex(
        /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)/,
        "Password must contain uppercase, lowercase, and number"
      ),
    confirmPassword: z.string(),
  })
  .refine((data) => data.password === data.confirmPassword, {
    message: "Passwords do not match",
    path: ["confirmPassword"],
  });

export const loginSchema = z.object({
  email: z.string().email("Invalid email address"),
  password: z
    .string()
    .min(8, "Password must be between 8 and 25 characters")
    .max(25),
});

export const verifySchema = z.object({
  code: z.string().length(6, "Code must be 6 digits"),
});

export const taskSchema = z.object({
  title: z
    .string()
    .min(1, "Title is required")
    .max(255, "Title must be at most 255 characters"),
  description: z.string().optional(),
  dueDate: z.string().optional(), // dueDate must be a valid ISO 8601 date string
});

export type SignupInput = z.infer<typeof signupSchema>;
export type LoginInput = z.infer<typeof loginSchema>;
export type VerifyInput = z.infer<typeof verifySchema>;
export type TaskInput = z.infer<typeof taskSchema>;
