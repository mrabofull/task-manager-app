import { Injectable, NotFoundException } from '@nestjs/common';
import { CreateTaskDto } from './dto/create-task.dto';
import { UpdateTaskDto } from './dto/update-task.dto';
import { InjectRepository } from '@nestjs/typeorm';
import { Like, Repository } from 'typeorm';
import { Task } from './entities/task.entity';
import { QueryTasksDto } from './dto/query-tasks.dto';

@Injectable()
export class TasksService {
  constructor(
    @InjectRepository(Task)
    private readonly tasksRepository: Repository<Task>,
  ) {}

  async create(createTaskDto: CreateTaskDto, userId: string): Promise<Task> {
    const task = this.tasksRepository.create({
      ...createTaskDto,
      user: { id: userId },
    });

    const savedTask = await this.tasksRepository.save(task);

    const { user, ...taskWithoutUser } = savedTask;
    return { ...taskWithoutUser, userId: user.id } as any;
  }

  async findAll(userId: string, queryDto: QueryTasksDto) {
    const { page = 1, limit = 10, search, sort = 'DESC', done } = queryDto;
    const skip = (page - 1) * limit;

    const where: any = {
      user: { id: userId },
    };

    if (search) {
      where.title = Like(`%${search}%`);
    }

    if (done !== undefined) {
      where.done = done;
    }

    const [tasks, total] = await this.tasksRepository.findAndCount({
      where,
      order: {
        createdAt: sort,
      },
      skip,
      take: limit,
      select: {
        id: true,
        title: true,
        description: true,
        dueDate: true,
        done: true,
        createdAt: true,
        updatedAt: true,
      },
    });

    return {
      data: tasks,
      meta: {
        total,
        page,
        limit,
        totalPages: Math.ceil(total / limit),
        hasNextPage: page < Math.ceil(total / limit),
        hasPreviousPage: page > 1,
      },
    };
  }

  async findOne(id: string, userId: string): Promise<Task> {
    const task = await this.tasksRepository.findOne({
      where: {
        id,
        user: { id: userId },
      },
      select: {
        id: true,
        title: true,
        description: true,
        dueDate: true,
        done: true,
        createdAt: true,
        updatedAt: true,
      },
    });

    if (!task) {
      throw new NotFoundException(`Task with ID ${id} not found`);
    }

    return task;
  }

  async update(
    id: string,
    updateTaskDto: UpdateTaskDto,
    userId: string,
  ): Promise<Task> {
    const task = await this.findOne(id, userId);

    await this.tasksRepository.update(
      { id, user: { id: userId } },
      updateTaskDto,
    );

    return this.findOne(id, userId);
  }

  async remove(id: string, userId: string): Promise<void> {
    const task = await this.findOne(id, userId);

    await this.tasksRepository.delete({
      id,
      user: { id: userId },
    });
  }
}
