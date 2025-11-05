import { Injectable } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { User } from './entities/user.entity';
import { Repository } from 'typeorm';

@Injectable()
export class UsersService {
  constructor(
    @InjectRepository(User)
    private readonly usersRepository: Repository<User>,
  ) {}

  private normalizeEmail(email: string): string {
    return email.toLowerCase().trim();
  }

  async create(
    email: string,
    name: string,
    passwordHash: string,
  ): Promise<User> {
    const user = this.usersRepository.create({
      email: this.normalizeEmail(email),
      name,
      passwordHash,
    });
    return this.usersRepository.save(user);
  }

  async findByEmail(email: string): Promise<User | null> {
    return this.usersRepository.findOne({
      where: { email: this.normalizeEmail(email) },
    });
  }

  async findById(id: string): Promise<User | null> {
    return this.usersRepository.findOne({ where: { id } });
  }

  async markEmailAsVerified(userId: string): Promise<void> {
    await this.usersRepository.update(userId, {
      emailVerifiedAt: new Date(),
    });
  }
}
