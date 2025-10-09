import { Routes, Route, Navigate } from "react-router-dom";
import { Login } from "@/pages/Login";
import { Signup } from "@/pages/Signup";
import { Verify } from "@/pages/Verify";
import { Tasks } from "@/pages/Tasks";
import { ProtectedRoute } from "@/components/layout/ProtectedRoute";

function App() {
  return (
    <Routes>
      <Route path="/" element={<Navigate to="/tasks" replace />} />
      <Route path="/login" element={<Login />} />
      <Route path="/signup" element={<Signup />} />
      <Route path="/verify" element={<Verify />} />
      <Route
        path="/tasks"
        element={
          <ProtectedRoute>
            <Tasks />
          </ProtectedRoute>
        }
      />
    </Routes>
  );
}

export default App;
