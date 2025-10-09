import { useState, useEffect } from "react";
import { useNavigate } from "react-router-dom";
import { useForm } from "react-hook-form";
import { zodResolver } from "@hookform/resolvers/zod";
import { toast } from "sonner";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import {
  Card,
  CardContent,
  CardDescription,
  CardFooter,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { authAPI } from "@/lib/api";
import { verifySchema } from "@/lib/validations";
import { useAuthStore } from "@/stores/authStore";
import { z } from "zod";

type VerifyInput = z.infer<typeof verifySchema>;

export function Verify() {
  const navigate = useNavigate();
  const { verificationEmail, setUser, setVerificationEmail } = useAuthStore();
  const [isLoading, setIsLoading] = useState(false);
  const [resendCooldown, setResendCooldown] = useState(0);

  const {
    register,
    handleSubmit,
    formState: { errors },
  } = useForm<VerifyInput>({
    resolver: zodResolver(verifySchema),
  });

  useEffect(() => {
    if (!verificationEmail) {
      navigate("/signup");
    }
  }, [verificationEmail, navigate]);

  useEffect(() => {
    if (resendCooldown > 0) {
      const timer = setTimeout(
        () => setResendCooldown(resendCooldown - 1),
        1000
      );
      return () => clearTimeout(timer);
    }
  }, [resendCooldown]);

  const onSubmit = async (data: VerifyInput) => {
    if (!verificationEmail) return;

    setIsLoading(true);
    try {
      await authAPI.verify({ email: verificationEmail, code: data.code });
      setUser({ email: verificationEmail });
      setVerificationEmail(null);
      toast.success("Email verified! You are now logged in.");
      navigate("/tasks");
    } catch (error: any) {
      toast.error(error.message);
    } finally {
      setIsLoading(false);
    }
  };

  const resendCode = async () => {
    if (!verificationEmail || resendCooldown > 0) return;

    try {
      await authAPI.resendCode({ email: verificationEmail });
      toast.success("New verification code sent!");
      setResendCooldown(60);
    } catch (error: any) {
      toast.error(error.message);
    }
  };

  return (
    <div className="min-h-screen flex items-center justify-center bg-slate-50">
      <Card className="w-full max-w-md">
        <CardHeader>
          <CardTitle>Verify Your Email</CardTitle>
          <CardDescription>
            We sent a 6-digit code to {verificationEmail}
          </CardDescription>
        </CardHeader>
        <form onSubmit={handleSubmit(onSubmit)}>
          <CardContent className="space-y-4">
            <div className="space-y-2">
              <Label htmlFor="code">Verification Code</Label>
              <Input
                id="code"
                placeholder="000000"
                maxLength={6}
                {...register("code")}
                disabled={isLoading}
                className="text-center text-2xl tracking-widest"
              />
              {errors.code && (
                <p className="text-sm text-red-600">{errors.code.message}</p>
              )}
            </div>
          </CardContent>
          <CardFooter className="flex flex-col space-y-2">
            <Button type="submit" className="w-full" disabled={isLoading}>
              {isLoading ? "Verifying..." : "Verify Email"}
            </Button>
            <Button
              type="button"
              variant="outline"
              className="w-full"
              onClick={resendCode}
              disabled={resendCooldown > 0}
            >
              {resendCooldown > 0
                ? `Resend code in ${resendCooldown}s`
                : "Resend Code"}
            </Button>
          </CardFooter>
        </form>
      </Card>
    </div>
  );
}
