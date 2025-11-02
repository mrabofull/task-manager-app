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

  async create(
    email: string,
    name: string,
    passwordHash: string,
  ): Promise<User> {
    const user = this.usersRepository.create({
      email,
      name,
      passwordHash,
    });
    return this.usersRepository.save(user);
  }

  async findByEmail(email: string): Promise<User | null> {
    return this.usersRepository.findOne({ where: { email } });
  }

  async findByUsername(name: string): Promise<User | null> {
    return this.usersRepository.findOne({ where: { name } });
  }

  async findById(id: string): Promise<User | null> {
    return this.usersRepository.findOne({ where: { id } });
  }

  async markEmailAsVerified(userId: string): Promise<void> {
    await this.usersRepository.update(userId, {
      emailVerifiedAt: new Date(),
    });
  }

  async incrementFailedLoginAttempts(user: User): Promise<void> {
    user.failedLoginCount++;

    // Exponential backoff: 1min, 2min, 4min, 8min, 16min, max 30min
    if (user.failedLoginCount >= 3) {
      const delayMinutes = Math.min(Math.pow(2, user.failedLoginCount - 3), 30);
      user.lockoutUntil = new Date(Date.now() + delayMinutes * 60 * 1000);
    }

    await this.usersRepository.save(user);
    //user.failedLoginCount++;

    // Lock account after 3 failed attempts (2 minutes)
    // if (user.failedLoginCount >= 3) {
    //   user.lockoutUntil = new Date(Date.now() + 2 * 60 * 1000); // 2 minutes from now
    // }

    //await this.usersRepository.save(user);
  }

  async resetFailedLoginAttempts(user: User): Promise<void> {
    user.failedLoginCount = 0;
    user.lockoutUntil = null;
    await this.usersRepository.save(user);
  }

  async unlockIfExpired(user: User): Promise<void> {
    if (user.lockoutUntil && user.lockoutUntil <= new Date()) {
      user.failedLoginCount = 0;
      user.lockoutUntil = null;
      await this.usersRepository.save(user);
    }
  }
}
