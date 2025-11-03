import { useState, useEffect } from "react";
import { Plus, Search, LogOut, Trash2, Edit } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Card, CardContent } from "@/components/ui/card";
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogFooter,
} from "@/components/ui/dialog";
import { Label } from "@/components/ui/label";
import { Textarea } from "@/components/ui/textarea";
import { Checkbox } from "@/components/ui/checkbox";
import { useNavigate } from "react-router-dom";
import { useForm } from "react-hook-form";
import { zodResolver } from "@hookform/resolvers/zod";
import { toast } from "sonner";
import { authAPI, tasksAPI } from "@/lib/api";
import { taskSchema, type TaskInput } from "@/lib/validations";
import { useAuthStore } from "@/stores/authStore";
import type { Task } from "@/types";

export function Tasks() {
  const navigate = useNavigate();
  const { user, logout } = useAuthStore();
  const [tasks, setTasks] = useState<Task[]>([]);
  const [loading, setLoading] = useState(true);
  const [searchTerm, setSearchTerm] = useState("");
  const [filterDone, setFilterDone] = useState<boolean | null>(null);
  const [isCreateDialogOpen, setIsCreateDialogOpen] = useState(false);
  const [editingTask, setEditingTask] = useState<Task | null>(null);
  const [page, setPage] = useState(1);
  const [totalPages, setTotalPages] = useState(1);

  const {
    register,
    handleSubmit,
    reset,
    setValue,
    formState: { errors, isSubmitting },
  } = useForm<TaskInput>({
    resolver: zodResolver(taskSchema),
  });

  useEffect(() => {
    loadTasks();
  }, [page, searchTerm, filterDone]);

  const loadTasks = async () => {
    try {
      setLoading(true);
      const params: any = { page, limit: 10 };
      if (searchTerm) params.search = searchTerm;
      if (filterDone !== null) params.done = filterDone;

      const response = await tasksAPI.getAll(params);
      setTasks(response.data);
      setTotalPages(response.meta.totalPages);
    } catch (error: any) {
      toast.error(error.message);
    } finally {
      setLoading(false);
    }
  };

  const handleLogout = async () => {
    try {
      await authAPI.logout();
      logout();
      toast.success("Logged out successfully");
      navigate("/login");
    } catch (error) {
      toast.error("Failed to logout");
    }
  };

  const onSubmit = async (data: TaskInput) => {
    try {
      if (editingTask) {
        await tasksAPI.update(editingTask.id, data);
        toast.success("Task updated successfully");
      } else {
        await tasksAPI.create(data);
        toast.success("Task created successfully");
      }
      setIsCreateDialogOpen(false);
      setEditingTask(null);
      reset();
      loadTasks();
    } catch (error: any) {
      toast.error(error.message);
    }
  };

  const toggleTaskDone = async (task: Task) => {
    try {
      await tasksAPI.update(task.id, { done: !task.done });
      setTasks(
        tasks.map((t) => (t.id === task.id ? { ...t, done: !t.done } : t))
      );
      toast.success(
        task.done ? "Task marked as incomplete" : "Task completed!"
      );
    } catch (error: any) {
      toast.error(error.message);
    }
  };

  const deleteTask = async (id: string) => {
    if (!confirm("Are you sure you want to delete this task?")) return;

    try {
      await tasksAPI.delete(id);
      toast.success("Task deleted");
      if (tasks.length === 1 && page > 1) {
        setPage(page - 1);
      } else {
        loadTasks();
      }
    } catch (error: any) {
      toast.error(error.message);
    }
  };

  const openEditDialog = (task: Task) => {
    setEditingTask(task);
    setValue("title", task.title);
    setValue("description", task.description || "");
    setValue("dueDate", task.dueDate || "");
    setIsCreateDialogOpen(true);
  };

  const closeDialog = () => {
    setIsCreateDialogOpen(false);
    setEditingTask(null);
    reset();
  };

  return (
    <div className="min-h-screen bg-slate-50">
      {/* Header */}
      <div className="bg-white shadow-sm border-b">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-4">
          <div className="flex flex-col sm:flex-row justify-between items-start sm:items-center gap-2">
            <h1 className="text-xl sm:text-2xl font-bold">Task Manager</h1>
            <div className="flex items-center gap-2 sm:gap-4">
              <span className="text-sm text-slate-600 truncate max-w-[150px] sm:max-w-none">
                {user?.name || user?.email}
              </span>
              <Button onClick={handleLogout} variant="outline" size="sm">
                <LogOut className="h-4 w-4 sm:mr-2" />
                <span className="hidden sm:inline">Logout</span>
              </Button>
            </div>
          </div>
        </div>
      </div>

      {/* Main Content */}
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
        {/* Controls */}
        <Card className="mb-6">
          <CardContent className="p-4">
            <div className="flex flex-col gap-4">
              {/* Search and New Task - Always visible */}
              <div className="flex gap-2">
                <div className="relative flex-1">
                  <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 text-slate-400 h-4 w-4" />
                  <Input
                    placeholder="Search tasks..."
                    value={searchTerm}
                    onChange={(e) => setSearchTerm(e.target.value)}
                    className="pl-10"
                  />
                </div>
                <Button
                  onClick={() => setIsCreateDialogOpen(true)}
                  className="shrink-0"
                >
                  <Plus className="h-4 w-4 sm:mr-2" />
                  <span className="hidden sm:inline">New Task</span>
                </Button>
              </div>

              {/* Filter buttons - Responsive */}
              <div className="flex gap-2">
                {/* Mobile: Dropdown */}
                <select
                  className="sm:hidden flex-1 px-3 py-2 border rounded-md"
                  value={
                    filterDone === null ? "all" : filterDone ? "done" : "active"
                  }
                  onChange={(e) => {
                    const val = e.target.value;
                    setFilterDone(val === "all" ? null : val === "done");
                  }}
                >
                  <option value="all">All Tasks</option>
                  <option value="active">Active</option>
                  <option value="done">Completed</option>
                </select>

                {/* Desktop: Button group */}
                <div className="hidden sm:flex gap-2">
                  <Button
                    variant={filterDone === null ? "default" : "outline"}
                    size="sm"
                    onClick={() => setFilterDone(null)}
                  >
                    All
                  </Button>
                  <Button
                    variant={filterDone === false ? "default" : "outline"}
                    size="sm"
                    onClick={() => setFilterDone(false)}
                  >
                    Active
                  </Button>
                  <Button
                    variant={filterDone === true ? "default" : "outline"}
                    size="sm"
                    onClick={() => setFilterDone(true)}
                  >
                    Completed
                  </Button>
                </div>
              </div>
            </div>
          </CardContent>
        </Card>

        {/* Tasks List */}
        {loading ? (
          <div className="text-center py-8">Loading tasks...</div>
        ) : tasks.length === 0 ? (
          <Card>
            <CardContent className="text-center py-12">
              <p className="text-slate-500 mb-4">No tasks found</p>
              <Button onClick={() => setIsCreateDialogOpen(true)}>
                Create your first task
              </Button>
            </CardContent>
          </Card>
        ) : (
          <>
            <div className="space-y-3">
              {tasks.map((task) => (
                <Card
                  key={task.id}
                  className={`overflow-hidden ${task.done ? "opacity-75" : ""}`}
                >
                  <CardContent className="p-4">
                    <div className="flex items-start gap-3">
                      <Checkbox
                        checked={task.done}
                        onCheckedChange={() => toggleTaskDone(task)}
                        className="mt-1 flex-shrink-0"
                      />
                      <div className="flex-1 min-w-0 overflow-hidden">
                        <h3
                          className={`font-medium break-all ${
                            task.done ? "line-through text-slate-500" : ""
                          }`}
                        >
                          {task.title}
                        </h3>
                        {task.description && (
                          <p className="text-sm text-slate-600 mt-1 break-all whitespace-pre-wrap">
                            {task.description}
                          </p>
                        )}
                        {task.dueDate && (
                          <p className="text-xs text-slate-500 mt-2">
                            Due: {new Date(task.dueDate).toLocaleDateString()}
                          </p>
                        )}
                      </div>
                      <div className="flex gap-2 flex-shrink-0">
                        <Button
                          size="sm"
                          variant="ghost"
                          onClick={() => openEditDialog(task)}
                        >
                          <Edit className="h-4 w-4" />
                        </Button>
                        <Button
                          size="sm"
                          variant="ghost"
                          onClick={() => deleteTask(task.id)}
                        >
                          <Trash2 className="h-4 w-4 text-red-500" />
                        </Button>
                      </div>
                    </div>
                  </CardContent>
                </Card>
              ))}
            </div>

            {/* Pagination */}
            {totalPages > 1 && (
              <div className="flex justify-center gap-2 mt-6">
                <Button
                  variant="outline"
                  onClick={() => setPage(page - 1)}
                  disabled={page === 1}
                >
                  Previous
                </Button>
                <span className="py-2 px-4">
                  Page {page} of {totalPages}
                </span>
                <Button
                  variant="outline"
                  onClick={() => setPage(page + 1)}
                  disabled={page === totalPages}
                >
                  Next
                </Button>
              </div>
            )}
          </>
        )}
      </div>

      {/* Create/Edit Dialog */}
      <Dialog open={isCreateDialogOpen} onOpenChange={setIsCreateDialogOpen}>
        <DialogContent className="max-w-2xl max-h-[90vh] overflow-y-auto">
          <DialogHeader>
            <DialogTitle>
              {editingTask ? "Edit Task" : "Create New Task"}
            </DialogTitle>
          </DialogHeader>
          <form onSubmit={handleSubmit(onSubmit)}>
            <div className="space-y-4 py-4">
              <div className="space-y-2">
                <Label htmlFor="title">Title</Label>
                <Input id="title" {...register("title")} className="w-full" />
                {errors.title && (
                  <p className="text-sm text-red-600">{errors.title.message}</p>
                )}
              </div>
              <div className="space-y-2">
                <Label htmlFor="description">Description (optional)</Label>
                <Textarea
                  id="description"
                  {...register("description")}
                  className="w-full min-h-[100px] resize-none"
                  style={{ wordBreak: "break-word" }}
                />
              </div>
              <div className="space-y-2">
                <Label htmlFor="dueDate">Due Date (optional)</Label>
                <Input
                  id="dueDate"
                  type="datetime-local"
                  {...register("dueDate")}
                  className="w-full"
                />
              </div>
            </div>
            <DialogFooter>
              <Button type="button" variant="outline" onClick={closeDialog}>
                Cancel
              </Button>
              <Button type="submit" disabled={isSubmitting}>
                {isSubmitting ? "Saving..." : editingTask ? "Update" : "Create"}
              </Button>
            </DialogFooter>
          </form>
        </DialogContent>
      </Dialog>
    </div>
  );
}
