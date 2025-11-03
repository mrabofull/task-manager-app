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
import { Clock, Mail } from "lucide-react";

type VerifyInput = z.infer<typeof verifySchema>;

export function Verify() {
  const navigate = useNavigate();
  const {
    verificationEmail,
    verificationExpiresAt,
    setUser,
    setVerificationEmail,
    setVerificationExpiry,
  } = useAuthStore();
  const [isLoading, setIsLoading] = useState(false);
  const [resendCooldown, setResendCooldown] = useState(0);
  const [timeLeft, setTimeLeft] = useState(0);

  const {
    register,
    handleSubmit,
    formState: { errors },
  } = useForm<VerifyInput>({
    resolver: zodResolver(verifySchema),
  });

  // Redirect if no email
  useEffect(() => {
    if (!verificationEmail) {
      navigate("/signup");
    }
  }, [verificationEmail, navigate]);

  // Countdown timer for code expiry
  useEffect(() => {
    if (!verificationExpiresAt) return;

    const timer = setInterval(() => {
      const now = new Date().getTime();
      const expiry = new Date(verificationExpiresAt).getTime();
      const diff = Math.max(0, Math.floor((expiry - now) / 1000));

      setTimeLeft(diff);

      if (diff === 0) {
        clearInterval(timer);
        toast.error("Verification code expired. Please request a new one.");
      }
    }, 1000);

    return () => clearInterval(timer);
  }, [verificationExpiresAt]);

  // Resend cooldown timer
  useEffect(() => {
    if (resendCooldown > 0) {
      const timer = setTimeout(
        () => setResendCooldown(resendCooldown - 1),
        1000
      );
      return () => clearTimeout(timer);
    }
  }, [resendCooldown]);

  const formatTime = (seconds: number) => {
    const mins = Math.floor(seconds / 60);
    const secs = seconds % 60;
    return `${mins}:${secs.toString().padStart(2, "0")}`;
  };

  const onSubmit = async (data: VerifyInput) => {
    if (!verificationEmail) return;

    setIsLoading(true);
    try {
      const response = await authAPI.verify({
        email: verificationEmail,
        code: data.code,
      });

      if (response.user) {
        setUser(response.user);
      }
      setVerificationEmail(null);
      setVerificationExpiry(null);
      toast.success("Successfully verified!");
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
      const response = await authAPI.resendCode({ email: verificationEmail });

      if (response.expiresAt) {
        setVerificationExpiry(response.expiresAt);
      }

      toast.success(response.message);
      setResendCooldown(60);
    } catch (error: any) {
      toast.error(error.message);
    }
  };

  return (
    <div className="min-h-screen flex items-center justify-center bg-gradient-to-br from-slate-50 to-slate-100 p-4">
      <Card className="w-full max-w-md">
        <CardHeader>
          <CardTitle className="text-2xl">Email Verification</CardTitle>
          <CardDescription className="flex items-center gap-2">
            <Mail className="h-4 w-4" />
            Code was sent to {verificationEmail}
          </CardDescription>
        </CardHeader>
        <form onSubmit={handleSubmit(onSubmit)}>
          <CardContent className="space-y-4">
            {timeLeft > 0 && (
              <div className="flex items-center justify-center gap-2 text-sm bg-blue-50 text-blue-700 p-3 rounded-lg">
                <Clock className="h-4 w-4" />
                <span>
                  Code expires in: <strong>{formatTime(timeLeft)}</strong>
                </span>
              </div>
            )}

            {timeLeft === 0 && (
              <div className="text-center text-sm bg-red-50 text-red-700 p-3 rounded-lg">
                Code expired. Please request a new one.
              </div>
            )}

            <div className="space-y-2">
              <Label htmlFor="code">Verification Code</Label>
              <Input
                id="code"
                placeholder="000000"
                maxLength={6}
                {...register("code")}
                disabled={isLoading || timeLeft === 0}
                className="text-center text-2xl tracking-[0.5em] font-mono"
                autoComplete="one-time-code"
                inputMode="numeric"
                pattern="[0-9]*"
                aria-label="Enter 6-digit verification code"
              />
              {errors.code && (
                <p className="text-sm text-red-600">{errors.code.message}</p>
              )}
            </div>

            <p className="text-xs text-center text-slate-600">
              Enter the 6-digit code from your email
            </p>
          </CardContent>
          <CardFooter className="flex flex-col space-y-3">
            <Button
              type="submit"
              className="w-full"
              disabled={isLoading || timeLeft === 0}
            >
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
