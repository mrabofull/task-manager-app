import { InjectRepository } from '@nestjs/typeorm';
import { UserSession } from '../entities/user-session.entity';
import { Repository } from 'typeorm';
import { User } from 'src/users/entities/user.entity';
import { Injectable } from '@nestjs/common';

@Injectable()
export class SessionService {
  constructor(
    @InjectRepository(UserSession)
    private sessionRepository: Repository<UserSession>,
  ) {}

  async createSession(
    user: User,
    refreshToken: string,
    userAgent?: string,
    ipAddress?: string,
  ): Promise<UserSession> {
    const sessions = await this.sessionRepository.find({
      where: { user: { id: user.id } },
      order: { lastUsedAt: 'ASC' },
    });

    if (sessions.length >= 3) {
      await this.sessionRepository.delete(sessions[0].id);
    }

    const session = this.sessionRepository.create({
      user,
      refreshToken,
      userAgent,
      ipAddress,
      lastUsedAt: new Date(),
    });

    return this.sessionRepository.save(session);
  }

  async findByRefreshToken(refreshToken: string): Promise<UserSession | null> {
    return this.sessionRepository.findOne({
      where: { refreshToken },
      relations: ['user'],
    });
  }

  async updateLastUsed(sessionId: string): Promise<void> {
    await this.sessionRepository.update(sessionId, {
      lastUsedAt: new Date(),
    });
  }

  async deleteSession(refreshToken: string): Promise<void> {
    await this.sessionRepository.delete({ refreshToken });
  }

  async deleteAllUserSessions(userId: string): Promise<void> {
    await this.sessionRepository.delete({ user: { id: userId } });
  }
}
